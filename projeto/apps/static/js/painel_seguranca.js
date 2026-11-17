/* Gráficos do painel de segurança.
 * Os dados chegam por json_script (#dados-graficos), já escapados pelo Django.
 * Cores lidas dos tokens CSS, então o modo escuro vale também para os gráficos. */
(function () {
    'use strict';

    // Filtros: aplicam ao mudar (o form funciona sem JS pelo botão em <noscript>).
    document.querySelectorAll('[data-autoenvio]').forEach(function (el) {
        el.addEventListener('change', function () { document.getElementById('filtros').submit(); });
    });

    var fonte = document.getElementById('dados-graficos');
    if (!fonte || typeof Chart === 'undefined') { return; }
    var dados = JSON.parse(fonte.textContent);
    var graficos = [];

    function token(nome) {
        return getComputedStyle(document.documentElement).getPropertyValue(nome).trim();
    }

    function preencherTabelaSerie() {
        var corpo = document.getElementById('t-serie');
        if (!corpo) { return; }
        corpo.textContent = '';
        dados.serie.rotulos.forEach(function (rotulo, i) {
            var tr = document.createElement('tr');
            [rotulo, dados.serie.falhas[i], dados.serie.anomalias[i]].forEach(function (v, j) {
                var td = document.createElement('td');
                td.textContent = v;           // textContent: nada vira HTML
                if (j) { td.className = 'text-end num'; }
                tr.appendChild(td);
            });
            corpo.appendChild(tr);
        });
    }

    function base(cores) {
        return {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            plugins: {
                legend: { display: false },     // uma série por gráfico: o título nomeia
                tooltip: {
                    backgroundColor: cores.superficie, titleColor: cores.texto1, bodyColor: cores.texto1,
                    borderColor: cores.borda, borderWidth: 1, padding: 10, displayColors: false,
                },
            },
            scales: {
                x: { grid: { display: false }, border: { color: cores.grade },
                     ticks: { color: cores.texto2, maxRotation: 0, autoSkipPadding: 12 } },
                y: { beginAtZero: true, grid: { color: cores.grade }, border: { display: false },
                     ticks: { color: cores.texto2, precision: 0 } },
            },
        };
    }

    function linha(id, valores, cores) {
        var el = document.getElementById(id);
        if (!el) { return; }
        var opcoes = base(cores);
        opcoes.interaction = { mode: 'index', intersect: false };   // crosshair + tooltip
        graficos.push(new Chart(el, {
            type: 'line',
            data: { labels: dados.serie.rotulos, datasets: [{
                data: valores, borderColor: cores.serie, backgroundColor: cores.serie,
                borderWidth: 2, pointRadius: 0, pointHoverRadius: 5, pointHitRadius: 12, tension: 0,
            }] },
            options: opcoes,
        }));
    }

    function barras(id, pares, cores) {
        var el = document.getElementById(id);
        if (!el) { return; }
        if (!pares.length) {
            el.parentNode.textContent = 'Sem dados no período.';
            return;
        }
        // Altura acompanha o nº de barras, para os rótulos não se espremerem.
        el.parentNode.style.height = Math.max(120, pares.length * 30 + 40) + 'px';
        var opcoes = base(cores);
        opcoes.indexAxis = 'y';
        opcoes.scales.x.grid = { color: cores.grade };
        opcoes.scales.x.ticks.precision = 0;
        opcoes.scales.y.grid = { display: false };
        opcoes.scales.y.beginAtZero = undefined;
        // Rótulo longo em tela estreita: corta com reticências (o tooltip mostra inteiro).
        var limite = Math.max(14, Math.floor(el.parentNode.clientWidth / 14));
        opcoes.scales.y.ticks.callback = function (valor) {
            var texto = this.getLabelForValue(valor);
            return texto.length > limite ? texto.slice(0, limite - 1) + '…' : texto;
        };
        graficos.push(new Chart(el, {
            type: 'bar',
            data: { labels: pares.map(function (p) { return p[0]; }), datasets: [{
                data: pares.map(function (p) { return p[1]; }),
                backgroundColor: cores.serie, borderRadius: 4, borderSkipped: 'start',
                barThickness: 14, maxBarThickness: 16,
            }] },
            options: opcoes,
        }));
    }

    function desenhar() {
        graficos.forEach(function (g) { g.destroy(); });
        graficos = [];
        var cores = {
            serie: token('--serie-1'), texto1: token('--texto-1'), texto2: token('--texto-2'),
            grade: token('--grade'), borda: token('--borda'), superficie: token('--superficie-1'),
        };
        Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;
        linha('g-falhas', dados.serie.falhas, cores);
        linha('g-anomalias', dados.serie.anomalias, cores);
        barras('g-motivo', dados.por_motivo, cores);
        barras('g-metodo', dados.por_metodo, cores);
        barras('g-tipo', dados.por_tipo, cores);
    }

    preencherTabelaSerie();
    desenhar();
    if (window.matchMedia) {
        var mq = window.matchMedia('(prefers-color-scheme: dark)');
        if (mq.addEventListener) { mq.addEventListener('change', desenhar); }
    }
})();
