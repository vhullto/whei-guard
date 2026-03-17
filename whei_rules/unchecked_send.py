from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.slithir.operations import Send, LowLevelCall
from slither.slithir.variables import TupleVariable


class UncheckedSend(AbstractDetector):
    """
    Detecta uso de .send() ou .call{value:...}() cujo valor de retorno
    não é verificado. Transferências com falha silenciosa podem causar
    perda de fundos ou inconsistência de estado.
    """

    ARGUMENT = "unchecked-send"
    HELP = "Retorno de .send() ou .call() não verificado"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://swcregistry.io/docs/SWC-104"
    WIKI_TITLE = "Unchecked Call Return Value"
    WIKI_DESCRIPTION = (
        "O retorno de .send() ou .call() não é verificado. "
        "Se a transferência falhar, o contrato continua executando normalmente, "
        "podendo causar inconsistência de estado ou perda silenciosa de ETH."
    )
    WIKI_EXPLOIT_SCENARIO = """
    contract Vulneravel {
        function pagar(address dest) public {
            dest.send(1 ether); // falha ignorada ❌
            // estado continua sendo atualizado mesmo se o pagamento falhou
        }
    }
    """
    WIKI_RECOMMENDATION = (
        "Sempre verifique o retorno de .send(): require(dest.send(valor), 'falhou'). "
        "Prefira .transfer() para reverter automaticamente, "
        "ou verifique explicitamente o bool retornado por .call()."
    )

    def _detect(self):
        resultados = []

        for contrato in self.contracts:
            for funcao in contrato.functions:
                for no in funcao.nodes:
                    for op in no.irs:
                        # Detecta .send() não verificado
                        if isinstance(op, Send):
                            if not self._retorno_verificado(op, no, funcao):
                                info = [
                                    "Retorno de .send() não verificado: ",
                                    funcao,
                                    f"\n\t- Nó: {no}",
                                    "\n\t- Falha em .send() é silenciosa se não checada\n",
                                ]
                                resultados.append(self.generate_result(info))

                        # Detecta .call{value:}() não verificado
                        elif isinstance(op, LowLevelCall):
                            if op.call_value and not self._retorno_verificado(op, no, funcao):
                                info = [
                                    "Retorno de .call() com value não verificado: ",
                                    funcao,
                                    f"\n\t- Nó: {no}",
                                    "\n\t- Falha em .call() é silenciosa se não checada\n",
                                ]
                                resultados.append(self.generate_result(info))

        return resultados

    def _retorno_verificado(self, op, no_origem, funcao):
        """
        Verifica se o valor de retorno da operação é usado
        em alguma condição subsequente na função.
        """
        if not hasattr(op, "lvalue") or op.lvalue is None:
            return False

        lvalue = op.lvalue
        for no in funcao.nodes:
            for outra_op in no.irs:
                lidos = getattr(outra_op, "read", []) or []
                if lvalue in lidos:
                    return True

        return False
