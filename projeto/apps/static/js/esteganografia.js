/* Dados sensíveis ficam apenas nesta página: nunca localStorage/cookies/URLs. */
(() => {
    "use strict";
    const el = (id) => document.getElementById(id);
    const ocultar = el("form-ocultar");
    const extrair = el("form-extrair");
    const numero = (valor, casas = 0) => Number(valor).toLocaleString("pt-BR", {
        minimumFractionDigits: casas, maximumFractionDigits: casas,
    });

    function informar(operacao, texto, erro = false) {
        const status = el(`status-${operacao}`);
        status.textContent = texto;
        status.classList.toggle("erro", erro);
    }

    function limpar(operacao) {
        el(`resultado-${operacao}`).hidden = true;
        el(`metricas-${operacao}`).replaceChildren();
        if (operacao === "ocultar") {
            el("imagem-resultado").removeAttribute("src");
            el("baixar-imagem").removeAttribute("href");
            el("chave-gerada").value = "";
            el("cifrado-ocultar").value = "";
        } else {
            el("mensagem-recuperada-grupo").hidden = true;
            el("mensagem-recuperada").value = "";
            el("cifrado-extraido").value = "";
        }
        informar(operacao, "");
    }

    function metricas(operacao, dados) {
        const linhas = [
            ["Dimensões", `${numero(dados.largura)} × ${numero(dados.altura)} pixels`],
            ["Capacidade para dados", `${numero(dados.capacidade_bytes)} bytes`],
            ["Dados ocultos", `${numero(dados.payload_bytes)} bytes`],
            ["Bits usados (com cabeçalho)", numero(dados.utilizados_bits)],
            ["Capacidade utilizada", `${numero(dados.capacidade_utilizada_percentual, 2)}%`],
        ];
        if (operacao === "ocultar") {
            linhas.push(["MSE (canais RGB)", numero(dados.mse, 6)]);
            linhas.push(["PSNR", dados.psnr === null ? "∞ dB (pixels idênticos)" : `${numero(dados.psnr, 2)} dB`]);
        }
        const lista = el(`metricas-${operacao}`);
        for (const [nome, valor] of linhas) {
            const termo = document.createElement("dt");
            const detalhe = document.createElement("dd");
            termo.textContent = nome;
            detalhe.textContent = valor;
            lista.append(termo, detalhe);
        }
    }

    function validarArquivo(form) {
        const arquivo = form.elements.imagem.files[0];
        if (!arquivo) throw new Error("Selecione uma imagem para continuar.");
        if (arquivo.size > Number(form.dataset.maxUploadBytes)) {
            throw new Error("A imagem excede o limite de tamanho informado.");
        }
    }

    async function enviar(form, dados) {
        const resposta = await fetch(form.action, {
            method: "POST", body: dados, credentials: "same-origin",
            headers: {"Accept": "application/json"}, cache: "no-store",
        });
        if (resposta.redirected || resposta.status === 401) {
            throw new Error("Sua sessão expirou. Entre novamente no sistema e tente de novo.");
        }
        const tipo = resposta.headers.get("Content-Type") || "";
        if (!tipo.includes("application/json")) {
            if (resposta.status === 403) {
                throw new Error("Não foi possível validar a sessão. Recarregue a página e tente novamente.");
            }
            throw new Error("O servidor não pôde processar a solicitação. Verifique o tamanho da imagem e tente novamente.");
        }
        const resultado = await resposta.json();
        if (!resposta.ok || !resultado.sucesso) {
            throw new Error(resultado.erro || "Não foi possível concluir a operação.");
        }
        return resultado;
    }

    function ocupar(form, ocupado) {
        form.setAttribute("aria-busy", String(ocupado));
        for (const campo of form.querySelectorAll("button, input, textarea")) campo.disabled = ocupado;
    }

    el("mensagem-original").addEventListener("input", () => {
        const tamanho = new TextEncoder().encode(el("mensagem-original").value).length;
        el("contador-mensagem").textContent = numero(tamanho);
    });

    // Modelo do cenário "mensagem privada cliente -> empresário" (só preenche o campo).
    el("usar-modelo").addEventListener("click", () => {
        const campo = el("mensagem-original");
        campo.value = "Mensagem privada para o empresário\nCafeteria: \nReserva: \nPedido especial: \nContato: ";
        campo.dispatchEvent(new Event("input"));
        campo.focus();
    });

    ocultar.addEventListener("submit", async (evento) => {
        evento.preventDefault();
        limpar("ocultar");
        try {
            validarArquivo(ocultar);
            const tamanho = new TextEncoder().encode(el("mensagem-original").value).length;
            if (tamanho > Number(ocultar.dataset.maxMensagemBytes)) {
                throw new Error("A mensagem excede o limite de bytes em UTF-8 informado.");
            }
            const dados = new FormData(ocultar);
            // Multipart normaliza strings com LF para CRLF. JSON mantém a
            // mensagem exata, inclusive quebras de linha e caracteres NUL.
            dados.delete("mensagem");
            dados.set("mensagem_json", JSON.stringify(el("mensagem-original").value));
            dados.set("chave", String(dados.get("chave") || "").trim());
            ocupar(ocultar, true);
            informar("ocultar", "Criptografando e ocultando a mensagem…");
            const resultado = await enviar(ocultar, dados);
            const imagem = `data:image/png;base64,${resultado.imagem_base64}`;
            el("imagem-resultado").src = imagem;
            el("baixar-imagem").href = imagem;
            el("chave-gerada").value = resultado.chave;
            el("cifrado-ocultar").value = resultado.texto_cifrado;
            metricas("ocultar", resultado.metricas);
            el("resultado-ocultar").hidden = false;
            informar("ocultar", "Mensagem ocultada com sucesso. Baixe o PNG e guarde a chave.");
        } catch (erro) {
            limpar("ocultar");
            informar("ocultar", erro instanceof TypeError ? "Falha de conexão. Verifique sua conexão e tente novamente." : erro.message, true);
        } finally {
            ocupar(ocultar, false);
        }
    });

    extrair.addEventListener("submit", async (evento) => {
        evento.preventDefault();
        limpar("extrair");
        try {
            validarArquivo(extrair);
            const soExtrair = evento.submitter && evento.submitter.value === "extrair";
            const chave = el("chave-extrair").value.trim();
            if (!soExtrair && !chave) throw new Error("Informe a chave para descriptografar a mensagem.");
            const dados = new FormData(extrair);
            dados.set("chave", soExtrair ? "" : chave);
            ocupar(extrair, true);
            informar("extrair", soExtrair ? "Extraindo o texto cifrado…" : "Extraindo e verificando a chave…");
            const resultado = await enviar(extrair, dados);
            el("cifrado-extraido").value = resultado.texto_cifrado;
            const decifrada = typeof resultado.mensagem === "string";
            el("mensagem-recuperada-grupo").hidden = !decifrada;
            el("mensagem-recuperada").value = decifrada ? resultado.mensagem : "";
            metricas("extrair", resultado.metricas);
            el("resultado-extrair").hidden = false;
            informar("extrair", decifrada ? "Integridade e chave verificadas. Mensagem original recuperada." : "Integridade dos dados verificada. Texto cifrado extraído; a chave ainda não foi verificada.");
        } catch (erro) {
            limpar("extrair");
            informar("extrair", erro instanceof TypeError ? "Falha de conexão. Verifique sua conexão e tente novamente." : erro.message, true);
        } finally {
            ocupar(extrair, false);
        }
    });

    el("copiar-chave").addEventListener("click", async () => {
        const campo = el("chave-gerada");
        if (!campo.value) return;
        try {
            await navigator.clipboard.writeText(campo.value);
            informar("ocultar", "Chave copiada. Guarde-a separadamente da imagem.");
        } catch (_erro) {
            campo.focus();
            campo.select();
            informar("ocultar", "Selecione e copie a chave com Ctrl+C ou com a opção Copiar do seu dispositivo.");
        }
    });

    el("baixar-chave").addEventListener("click", () => {
        const chave = el("chave-gerada").value;
        if (!chave) return;
        const url = URL.createObjectURL(new Blob([chave + "\n"], {type: "text/plain;charset=utf-8"}));
        const link = document.createElement("a");
        link.href = url;
        link.download = "chave-mensagem.txt";
        document.body.append(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    });
})();
