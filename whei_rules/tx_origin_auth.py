from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.slithir.operations import Binary, Condition
from slither.core.declarations.solidity_variables import SolidityVariableComposed


class TxOriginAuth(AbstractDetector):
    """
    Detecta uso de tx.origin para autenticação ou controle de acesso.
    tx.origin retorna o endereço que iniciou a transação original,
    tornando contratos vulneráveis a ataques de phishing.
    """

    ARGUMENT = "tx-origin-auth"
    HELP = "Uso de tx.origin para autenticação (phishável)"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://swcregistry.io/docs/SWC-115"
    WIKI_TITLE = "Authorization through tx.origin"
    WIKI_DESCRIPTION = (
        "O contrato usa tx.origin para verificar autorização. "
        "tx.origin é o endereço que iniciou a cadeia de chamadas, não o chamador imediato. "
        "Um contrato intermediário malicioso pode explorar isso para contornar a autenticação."
    )
    WIKI_EXPLOIT_SCENARIO = """
    contract Vulneravel {
        address dono;
        function transferir(address dest, uint valor) public {
            require(tx.origin == dono); // phishável ❌
            dest.transfer(valor);
        }
    }
    // Atacante cria contrato que chama transferir() quando a vítima interagir com ele
    """
    WIKI_RECOMMENDATION = (
        "Substitua tx.origin por msg.sender para controle de acesso. "
        "tx.origin só deve ser usado para verificar se o chamador é um EOA, "
        "nunca para autenticação de identidade."
    )

    def _detect(self):
        resultados = []

        for contrato in self.contracts:
            for funcao in contrato.functions:
                nos_com_txorigin = []

                for no in funcao.nodes:
                    for var in no.variables_read:
                        if (
                            isinstance(var, SolidityVariableComposed)
                            and var.name == "tx.origin"
                        ):
                            nos_com_txorigin.append(no)
                            break

                if nos_com_txorigin:
                    info = [
                        "Uso de tx.origin para autenticação: ",
                        funcao,
                        f"\n\t- Ocorrências: {len(nos_com_txorigin)} nó(s)",
                        "\n\t- tx.origin é phishável via contrato intermediário\n",
                    ]
                    resultados.append(self.generate_result(info))

        return resultados
