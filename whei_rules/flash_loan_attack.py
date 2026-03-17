"""
Detecta funcoes que executam logica critica em uma unica transacao
sem protecao contra flash loans (same-block manipulations).
"""
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.slithir.operations import HighLevelCall, LowLevelCall

IGNORAR = (
    "test/", "tests/", "mock", "Mock", "lib/",
    "scripts/", ".t.sol", ".s.sol", "node_modules/",
)

# Indicadores de recepcao de flash loan
FLASHLOAN_RECEIVERS = (
    "executeOperation",       # Aave
    "uniswapV2Call",          # Uniswap V2
    "uniswapV3FlashCallback", # Uniswap V3
    "pancakeCall",            # PancakeSwap
    "onFlashLoan",            # ERC3156
    "flashCallback",          # Balancer
    "receiveFlashLoan",       # Balancer V2
    "tokensToSend",           # ERC777
    "tokensReceived",         # ERC777
)

# Funcoes que tipicamente alteram estado e podem ser manipuladas
FUNCOES_CRITICAS = (
    "borrow", "liquidate", "mint", "redeem", "swap", "vote",
    "snapshot", "updateprice", "setprice", "rebalance",
)


class FlashLoanAttack(AbstractDetector):

    ARGUMENT = "flash-loan-attack"
    HELP = "Contrato implementa callback de flash loan com logica critica vulneravel"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://swcregistry.io/docs/SWC-107"
    WIKI_TITLE = "Flash Loan Attack Vector"
    WIKI_DESCRIPTION = (
        "O contrato implementa callbacks de flash loan que executam logica financeira critica. "
        "Isso pode permitir que atacantes manipulem o estado do contrato dentro de uma unica transacao."
    )
    WIKI_EXPLOIT_SCENARIO = """
    // Atacante:
    // 1. Pega flash loan de X tokens
    // 2. executeOperation() e chamado pelo protocolo
    // 3. Dentro do callback, manipula precos/estado
    // 4. Executa acao lucrativa com estado manipulado
    // 5. Repaga o flash loan
    // Tudo em uma transacao — sem capital proprio
    """
    WIKI_RECOMMENDATION = (
        "Implemente protecao contra reentrancia (ReentrancyGuard). "
        "Use TWAPs em vez de precos spot. "
        "Considere adicionar delays entre acoes criticas. "
        "Valide que o estado nao foi manipulado antes de executar logica critica."
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
                nome_func = funcao.name

                # Verifica se e um receiver de flash loan
                e_receiver = nome_func in FLASHLOAN_RECEIVERS
                if not e_receiver:
                    continue

                # Verifica se tem logica critica dentro do callback
                logica_critica = []
                for no in funcao.nodes:
                    for op in no.irs:
                        if isinstance(op, (HighLevelCall, LowLevelCall)):
                            fname = ""
                            if hasattr(op, "function") and op.function:
                                fname = getattr(op.function, "name", "").lower()
                            if any(c in fname for c in FUNCOES_CRITICAS):
                                logica_critica.append(fname)

                # Verifica se escreve em estado critico sem protecao
                vars_criticas = []
                for var in funcao.state_variables_written:
                    nome_var = var.name.lower()
                    if any(fin in nome_var for fin in (
                        "balance", "price", "rate", "supply", "reserve",
                        "total", "amount", "weight", "share",
                    )):
                        vars_criticas.append(var.name)

                # Verifica se tem ReentrancyGuard
                mods = {m.name.lower() for m in getattr(funcao, "modifiers", [])}
                tem_guard = any(g in mods for g in (
                    "nonreentrant", "reentrancyguard", "noreentrancy",
                ))

                if (logica_critica or vars_criticas) and not tem_guard:
                    info = [
                        "Callback de flash loan com logica critica sem protecao: ",
                        funcao,
                        f"\n\t- Callback: {nome_func}",
                        f"\n\t- Logica critica: {logica_critica or 'verificar manualmente'}",
                        f"\n\t- Variaveis de estado em risco: {vars_criticas or 'verificar manualmente'}",
                        f"\n\t- ReentrancyGuard: {'sim' if tem_guard else 'NAO'}",
                        "\n\t- Risco: manipulacao de estado via flash loan em uma transacao\n",
                    ]
                    resultados.append(self.generate_result(info))

        return resultados
