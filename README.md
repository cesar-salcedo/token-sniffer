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
   - GoPlus: honeypot, código verificado, propietario que altera saldos, propietario oculto, autodestrucción,
     tasas y si se pueden cambiar, acuñación, proxy, pausas, lista negra, concentración del top 10.
     En Solana: autoridad de acuñación, congelación, saldos mutables, comisiones y hooks de transferencia.
   - DexScreener: liquidez en DEX, número de pools, antigüedad, compras frente a ventas en 24 h.
7. **Nota final** ponderada (momentum 22 %, valoración 18 %, seguridad 14 %, fundamentales 12 %,
   liquidez 12 %, tokenomics 12 %, atención 10 %). Una señal sin datos cuenta como 45/100
   (un contrato sin auditar, 65): la falta de evidencia no suma.
8. **Selección** de 16: primero el mejor representante de cada uno de los nueve motivos, después relleno por
   nota, con cuotas por tramo, máximo 2 por sector y 2 por motivo. Se descarta cualquier contrato con un fallo
   crítico, y los tokens con liquidez en DEX inferior al 0,05 % de su capitalización sin exchange centralizado conocido.

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

## Fuentes

Todas públicas y sin clave: `api.coingecko.com`, `api.llama.fi`, `api.gopluslabs.io`, `api.dexscreener.com`.
El cliente respeta los límites de ritmo de cada API, reintenta con espera ante errores 429 y guarda una caché
local en `.cache/` (20 min para mercado, 12 h para fichas y auditorías).

## Limitaciones

- CoinGecko ya no ofrece actividad de GitHub ni datos de comunidad en la API gratuita: no hay señal de desarrollo.
- Los activos nativos de su propia cadena (L1) no tienen contrato que auditar.
- Las cadenas que no son EVM ni Solana (Sui, Aptos, TON, Cosmos…) quedan «sin auditar».
- Los datos de mercado pueden tener minutos de retraso y errores de la fuente.

**No es asesoramiento financiero.** Son señales cuantitativas automáticas. Investiga antes de invertir.
