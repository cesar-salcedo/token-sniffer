# Token Sniffer

Escáner de criptoactivos que localiza **16 monedas con potencial**, cada una por un motivo distinto,
repartidas en tres tramos de capitalización y en varios sectores.

| Tramo | Rango de capitalización | Plazas | Volumen mínimo diario |
|---|---|---|---|
| Baja cap | $15 M – $100 M | 6 | $250 mil |
| Baja-media | $100 M – $500 M | 5 | $1 M |
| Media cap | $500 M – $3.000 M | 5 | $3 M |

Sectores: Memes, IA, DePIN, RWA, Privacidad, Gaming, Oráculos e interop, Datos y storage,
DEX y derivados, Lending, DeFi, Layer 2 y ZK, Layer 1. Máximo dos selecciones por sector.

## Web pública

**https://cesar-salcedo.github.io/token-sniffer/**: los precios se actualizan solos; la selección, al pulsar «Re-escanear».
Los datos en bruto del último escaneo están en `scan.json` junto a la página.

## Uso

Solo necesita Python 3.9+ (librería estándar, sin dependencias).

```bash
python3 sniffer.py            # escanea (5-8 min) y genera dist/index.html
python3 sniffer.py serve      # interfaz en http://localhost:8000 con botón «Re-escanear ahora»
python3 sniffer.py --no-cache # fuerza datos frescos
python3 sniffer.py --build-only  # regenera la interfaz con el último escaneo
```

`dist/index.html` es autocontenido: se puede abrir con doble clic.
Cada escaneo guarda `data/scan.json` y un resumen en `data/history/` para comparar en el tiempo.

## Qué hace, paso a paso

1. **Universo.** Descarga de CoinGecko todas las monedas de los 13 sectores con su precio, capitalización,
   FDV, volumen, suministro, máximo histórico y el gráfico horario de 7 días.
2. **Limpieza.** Quita stablecoins, tokens envueltos/puenteados, de staking líquido, de exchanges y activos
   tokenizados (por categoría, por nombre y por comportamiento de paridad fija), y monedas sin volumen.
3. **Fundamentales.** Cruza con DefiLlama: TVL y su variación, comisiones e ingresos de 30 días frente al mes
   anterior, ratios capitalización/TVL, precio/comisiones y precio/ingresos. En protocolos de staking líquido,
   puentes o RWA el TVL son depósitos de usuarios y no se usa para valorar.
4. **Puntuación de mercado** para todo el universo: momentum (30 d, 7 d y limpieza de la tendencia),
   valoración, fundamentales, liquidez (rotación volumen/capitalización, con penalización si es anómala) y
   tokenomics (FDV frente a capitalización, % en circulación).
5. **Preselección** (~65 monedas): la mejor de cada sector y tramo, más las mejores de cada motivo.
6. **Análisis profundo** de la preselección:
   - CoinGecko: contrato, categorías, seguidores (atención por dólar de capitalización), sentimiento.
   - **Seguridad por consenso de tres auditores automáticos:**
     - GoPlus: honeypot, código verificado, propietario que altera saldos, propietario oculto, autodestrucción,
       tasas y si se pueden cambiar, acuñación, proxy, pausas, lista negra, concentración del top 10.
       En Solana: autoridad de acuñación, congelación, saldos mutables, comisiones y hooks de transferencia.
     - Honeypot.is (Ethereum, BNB Chain, Base): simula una compra y una venta reales y mide los impuestos efectivos.
     - RugCheck (Solana): riesgos del token, liquidez bloqueada, concentración.
     - Nota = 60 % GoPlus + 40 % segundo auditor. Un fallo crítico en **cualquiera** descarta la moneda; si las
       notas difieren más de 35 puntos se marca como «discrepan» y queda en precaución.
   - DexScreener: liquidez en DEX, número de pools, antigüedad, compras frente a ventas en 24 h.
7. **Nota final** ponderada (momentum 22 %, valoración 18 %, seguridad 14 %, fundamentales 12 %,
   liquidez 12 %, tokenomics 12 %, atención 10 %). Una señal sin datos cuenta como 45/100
   (un contrato sin auditar, 65): la falta de evidencia no suma.
8. **Selección** de 16: primero el mejor representante de cada uno de los nueve motivos, después relleno por
   nota, con cuotas por tramo, máximo 2 por sector y 2 por motivo. Se descarta cualquier contrato con un fallo
   crítico, y los tokens con liquidez en DEX inferior al 0,05 % de su capitalización sin exchange centralizado conocido.

### Zona shitcoin (4 micro-caps de alto riesgo)

Micro-caps de $1 M a $15 M entre las 1.000 monedas con más volumen de CoinGecko. Para entrar tienen que superar
**todos** estos filtros; si menos de cuatro los superan, se muestran menos (nunca se rellena):

- ≥ 10 días desde su primer pool, ≥ 250 operaciones diarias en DEX.
- Liquidez en DEX ≥ $75 mil y ≥ 3 % de su capitalización; ≥ 30 % de esa liquidez bloqueada o quemada
  (salvo proyectos de más de 6 meses que cotizan en exchanges centralizados).
- Contrato limpio en **todos** los auditores, sin acuñación ni congelación, impuestos ≤ 1 %, top 10 ≤ 35 %.
- Nada sobrecalentado (≤ +150 % en 7 días, ≤ +60 % en 24 h) ni subidas con promoción pagada en DexScreener.

Puntúan por tracción (operaciones, rotación de la liquidez, compras frente a ventas), momentum, solidez
(liquidez respecto a la capitalización, edad, holders, liquidez bloqueada) y seguridad; máximo dos por cadena.
Se siguen aparte en el seguimiento de aciertos y la web avisa de «posible rug» si su liquidez cae más de un 40 %.

### Los nueve motivos

| Motivo | Qué detecta |
|---|---|
| Tendencia sólida | +10 % en 30 d, positivo en 7 d, tendencia limpia y sin sobrecalentamiento |
| Infravalorado | Capitalización/TVL < 1,5×, precio/comisiones < 40× o precio/ingresos < 25× |
| Rebote desde mínimos | ≥ 75 % bajo su máximo histórico y girando al alza |
| Acumulación | Volumen ≥ 1,6× la mediana de su sector y tramo con el precio lateral |
| Crecimiento on-chain | TVL +5 % en 7 d o comisiones +20 % mes contra mes |
| Genera ingresos | Ingresos anualizados > 2 % de la capitalización |
| Fuerza relativa | +15 puntos sobre su sector y +10 sobre bitcoin en 30 d |
| Atención emergente | En tendencia en CoinGecko, o muchos seguidores para su tamaño con el precio acompañando |
| Tokenomics limpios | FDV ≈ capitalización, ≥ 90 % en circulación, nota ≥ 55 y mejor que su sector o barato |

## Actualización

| Qué | Cuándo | Dónde |
|---|---|---|
| Escaneo completo (mercado, notas, selección) | Al pulsar «Re-escanear» (5–8 min) | GitHub Actions (`.github/workflows/escaneo.yml`) |
| Fichas de CoinGecko y auditorías de contrato | Se reutilizan 24 h | Caché entre ejecuciones |
| Precios y liquidez de las 16 seleccionadas | Cada 1–2 min | En el navegador de quien abre la web |

El botón «Re-escanear» de la web abre **Actions → Re-escanear → Run workflow** (hace falta tu sesión de GitHub,
nadie más puede lanzarlo). El flujo guarda los resultados en `main`, publica la web en la rama `gh-pages` y, si es
el primer escaneo del día, guarda la cohorte en `data/history/`. La web abierta detecta el escaneo nuevo y ofrece
actualizarse.
La web muestra alertas en vivo si una selección cae más de un 15 % desde el escaneo o si su liquidez en DEX
baja más de un 40 %.

## Seguimiento de aciertos

Cada día UTC se guarda la primera selección como **cohorte** (`data/history/AAAA-MM-DD.json`) con sus precios,
el de BTC y los del universo. La web mide, para cada cohorte y a 7, 30 y 90 días:

- rentabilidad media de las 16 (mismo peso para todas),
- frente a BTC y frente a la mediana del universo,
- cuántas cohortes y qué porcentaje de monedas baten a BTC.

Sin comisiones ni deslizamiento. Es la forma de comprobar con datos si los criterios funcionan.

## Fuentes

Todas públicas y sin clave: `api.coingecko.com`, `api.llama.fi`, `api.gopluslabs.io`, `api.honeypot.is`,
`api.rugcheck.xyz`, `api.dexscreener.com`.
El cliente respeta los límites de ritmo de cada API, reintenta con espera ante errores 429 y guarda una caché
local en `.cache/` (25 min para mercado, 24 h para fichas y auditorías).

## Limitaciones

- CoinGecko ya no ofrece actividad de GitHub ni datos de comunidad en la API gratuita: no hay señal de desarrollo.
- Los activos nativos de su propia cadena (L1) no tienen contrato que auditar.
- Las cadenas que no son EVM ni Solana (Tron, Sui, Aptos, TON, Cosmos…) quedan «sin auditar». Honeypot.is solo
  simula en Ethereum, BNB Chain y Base; en Arbitrum, Polygon, Avalanche y Optimism solo opina GoPlus.
- Las auditorías son automáticas (banderas y simulaciones), no una revisión del código por personas.
- Los pesos y umbrales son criterio propio: el seguimiento de aciertos es lo que dirá si funcionan.
- Los datos de mercado pueden tener minutos de retraso y errores de la fuente.

**No es asesoramiento financiero.** Son señales cuantitativas automáticas. Investiga antes de invertir.
