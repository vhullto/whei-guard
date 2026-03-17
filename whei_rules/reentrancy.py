from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.slithir.operations import (
    HighLevelCall,
    LowLevelCall,
    Send,
    Transfer,
)

# Caminhos ignorados
IGNORAR = (
    "test/", "tests/", "mock", "Mock", "lib/",
    "scripts/", ".t.sol", ".s.sol", "node_modules/",
)

# Bibliotecas internas que nao representam chamadas externas reais
LIBS_INTERNAS = {
    "SafeMath", "SafeERC20", "Address", "Math", "SignedSafeMath",
    "EnumerableSet", "EnumerableMap", "Strings", "ECDSA", "MerkleProof",
    "EIP712", "MessageHashUtils", "SignatureChecker",
}


def _e_chamada_externa_real(op):
    """
    Retorna True apenas se a operacao e uma chamada externa de verdade.
    Filtra bibliotecas internas (SafeMath, Address, EIP712, etc),
    chamadas internas/privadas e artefatos do Foundry VM.
    """
    if isinstance(op, (LowLevelCall, Send, Transfer)):
        return True

    if isinstance(op, HighLevelCall):
        destino = getattr(op, "function", None)
        if destino:
            contrato_destino = getattr(destino, "contract", None)
            if contrato_destino:
                # E biblioteca Solidity
                if getattr(contrato_destino, "is_library", False):
                    return False
                # Nome esta na lista de libs conhecidas
                if contrato_destino.name in LIBS_INTERNAS:
                    return False
            # Chamada interna/privada nao e externa
            if getattr(destino, "visibility", "") in ("internal", "private"):
                return False

        # Filtra artefatos do Foundry e console.log
        str_op = str(op)
        if any(p in str_op for p in ("vm.", "console.", "OTHER_ENTRYPOINT")):
            return False

        return True

    return False


class Reentrancy(AbstractDetector):

    ARGUMENT = "reentrancy"
    HELP = "Chamada externa antes de atualizar estado (potencial reentrancia)"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://swcregistry.io/docs/SWC-107"
    WIKI_TITLE = "Reentrancy"
    WIKI_DESCRIPTION = (
        "A funcao realiza uma chamada externa antes de atualizar variaveis de estado. "
        "Um contrato malicioso pode re-entrar na funcao e drenar fundos ou corromper estado."
    )
    WIKI_EXPLOIT_SCENARIO = """
    contract Vulneravel {
        mapping(address => uint) saldos;
        function sacar() public {
            uint valor = saldos[msg.sender];
            (bool ok,) = msg.sender.call{value: valor}("");
            saldos[msg.sender] = 0;
        }
    }
    """
    WIKI_RECOMMENDATION = (
        "Siga o padrao Checks-Effects-Interactions: "
        "atualize todas as variaveis de estado ANTES de realizar chamadas externas. "
        "Considere tambem usar ReentrancyGuard da OpenZeppelin."
    )

    def _detect(self):
        resultados = []

        for contrato in self.contracts:
            arquivo = contrato.source_mapping.filename.absolute
            if any(p in arquivo for p in IGNORAR):
                continue

            # Pula bibliotecas
            if getattr(contrato, "is_library", False):
                continue

            for funcao in contrato.functions:
                if funcao.is_constructor:
                    continue

                # Pula funcoes internas/privadas — nao sao entry points externos
                if funcao.visibility in ("internal", "private"):
                    continue

                chamadas_externas = []
                escritas_apos_chamada = []
                encontrou_chamada = False

                for no in funcao.nodes:
                    for op in no.irs:
                        if _e_chamada_externa_real(op):
                            encontrou_chamada = True
                            chamadas_externas.append(no)
                        elif encontrou_chamada and no.state_variables_written:
                            escritas_apos_chamada.extend(no.state_variables_written)

                if chamadas_externas and escritas_apos_chamada:
                    variaveis = ", ".join(
                        v.name for v in dict.fromkeys(escritas_apos_chamada)
                    )
                    info = [
                        "Potencial reentrancia detectada: ",
                        funcao,
                        f"\n\t- Chamada externa em: {[str(n) for n in chamadas_externas]}",
                        f"\n\t- Estado atualizado apos chamada: {variaveis}",
                        "\n\t- Padrao CEI violado\n",
                    ]
                    resultados.append(self.generate_result(info))

        return resultados
