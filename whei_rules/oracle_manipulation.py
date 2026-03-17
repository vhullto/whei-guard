"""
Detecta uso de preco spot de DEX como oracle de preco —
vulneravel a manipulacao por flash loan.
"""
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification

IGNORAR = (
    "test/", "tests/", "mock", "Mock", "lib/",
    "scripts/", ".t.sol", ".s.sol", "node_modules/",
)

# Funcoes de DEX que retornam preco spot (manipulaveis)
SPOT_PRICE_CALLS = {
    # Uniswap V2
    "getreserves", "price0cumulativelast", "price1cumulativelast",
    # Uniswap V3
    "slot0", "observe", "observations",
    # Balancer
    "getlatestprice", "getpricefeed",
    # Curve
    "get_dy", "get_dy_underlying", "get_virtual_price",
    # Genericos suspeitos
    "getprice", "currentprice", "spotprice", "latestanswer",
}

# Funcoes que tipicamente usam o preco para decisoes financeiras
PRICE_USAGE_PATTERNS = (
    "borrow", "liquidate", "mint", "redeem", "swap",
    "collateral", "loan", "leverage", "flashloan",
)


class OracleManipulation(AbstractDetector):

    ARGUMENT = "oracle-manipulation"
    HELP = "Uso de preco spot de DEX como oracle — vulneravel a flash loan"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://swcregistry.io/docs/SWC-136"
    WIKI_TITLE = "Unencrypted Private Data On-Chain"
    WIKI_DESCRIPTION = (
        "O contrato usa o preco spot de uma DEX como referencia de preco. "
        "Isso e vulneravel a manipulacao por flash loan em uma unica transacao."
    )
    WIKI_EXPLOIT_SCENARIO = """
    // Atacante usa flash loan para manipular o preco no pool
    // Chama a funcao vulneravel com preco manipulado
    // Reverte o flash loan — lucro sem risco
    function getPrice() public view returns (uint) {
        (uint reserve0, uint reserve1,) = pair.getReserves(); // SPOT PRICE!
        return reserve1 / reserve0;
    }
    """
    WIKI_RECOMMENDATION = (
        "Use oracles resistentes a manipulacao como Chainlink, "
        "ou TWAPs (Time-Weighted Average Prices) do Uniswap V3. "
        "Nunca use preco spot de uma DEX para decisoes financeiras criticas."
    )

    def _detect(self):
        resultados = []

        for contrato in self.contracts:
            arquivo = contrato.source_mapping.filename.absolute
            if any(p in arquivo for p in IGNORAR):
                continue
            if getattr(contrato, "is_library", False):
                continue

            for funcao in contrato.functions:
                if funcao.visibility in ("internal", "private"):
                    continue

                nome_func = funcao.name.lower()
                usa_preco_financeiro = any(p in nome_func for p in PRICE_USAGE_PATTERNS)

                chamadas_spot = []
                for no in funcao.nodes:
                    no_str = str(no).lower()
                    for spot_call in SPOT_PRICE_CALLS:
                        if spot_call in no_str:
                            chamadas_spot.append(spot_call)

                if chamadas_spot:
                    info = [
                        "Possivel uso de preco spot manipulavel: ",
                        funcao,
                        f"\n\t- Chamadas de preco spot: {list(set(chamadas_spot))}",
                        f"\n\t- Funcao financeira: {'sim' if usa_preco_financeiro else 'verificar manualmente'}",
                        "\n\t- Risco: manipulacao por flash loan em uma transacao\n",
                    ]
                    resultados.append(self.generate_result(info))

        return resultados
