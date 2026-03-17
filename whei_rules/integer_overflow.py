"""
Detecta contratos Solidity < 0.8.0 sem SafeMath que fazem
operacoes aritmeticas em variaveis de estado (risco de overflow/underflow).
"""
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.slithir.operations import Binary, BinaryType
import re

IGNORAR = (
    "test/", "tests/", "mock", "Mock", "lib/",
    "scripts/", ".t.sol", ".s.sol", "node_modules/",
)

OPS_SUSPEITAS = {
    BinaryType.ADDITION, BinaryType.SUBTRACTION,
    BinaryType.MULTIPLICATION, BinaryType.DIVISION,
    BinaryType.POWER,
}

# Regex para extrair versao do pragma do arquivo do contrato
# Aceita: 0.6.12, ^0.7.6, >=0.6.0 <0.8.0, etc
_RE_PRAGMA = re.compile(
    r'pragma\s+solidity\s+'
    r'(?:[>=^~<]*)\s*'
    r'(0\.[4-7])\.'   # captura major.minor 0.4 a 0.7
)


def _arquivo_e_versao_antiga(arquivo: str) -> bool:
    """
    Le o pragma do arquivo .sol e retorna True se
    a versao maxima usavel e < 0.8.0.
    Exemplos que retornam True:
      pragma solidity 0.7.6;
      pragma solidity ^0.6.12;
      pragma solidity >=0.6.0 <0.8.0;
    Exemplos que retornam False:
      pragma solidity ^0.8.0;
      pragma solidity >=0.6.2 <0.9.0;  <- range inclui 0.8+
    """
    try:
        with open(arquivo, encoding="utf-8") as f:
            conteudo = f.read()

        # Caso simples: versao fixa ou caret/tilde em 0.4-0.7
        # ex: "pragma solidity 0.7.6" ou "pragma solidity ^0.6.12"
        match = _RE_PRAGMA.search(conteudo)
        if match:
            # Verifica se ha limite superior >= 0.8
            # ex: ">=0.6.2 <0.9.0" nao e versao antiga
            if "<0.8" in conteudo or "< 0.8" in conteudo:
                return True  # range explicitamente < 0.8
            if ">=0." in conteudo and "<0.9" in conteudo:
                return False  # range permite 0.8+
            if ">=0." in conteudo and "<0.8" not in conteudo:
                return False  # range aberto permite 0.8+
            return True  # versao fixa em 0.4-0.7

    except Exception:
        pass
    return False


def _arquivo_usa_safemath(arquivo: str) -> bool:
    """Le o codigo-fonte do arquivo e verifica uso de SafeMath."""
    try:
        with open(arquivo, encoding="utf-8") as f:
            conteudo = f.read().lower()
        return (
            "using safemath" in conteudo or
            "safemath.add" in conteudo or
            "safemath.sub" in conteudo or
            "safemath.mul" in conteudo or
            "safemath.div" in conteudo
        )
    except Exception:
        return False


class IntegerOverflow(AbstractDetector):

    ARGUMENT = "integer-overflow"
    HELP = "Operacao aritmetica sem SafeMath em Solidity < 0.8.0"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://swcregistry.io/docs/SWC-101"
    WIKI_TITLE = "Integer Overflow and Underflow"
    WIKI_DESCRIPTION = (
        "Contratos Solidity < 0.8.0 nao tem protecao nativa contra overflow/underflow. "
        "Sem SafeMath, operacoes aritmeticas podem transbordar silenciosamente."
    )
    WIKI_EXPLOIT_SCENARIO = """
    // Solidity 0.6.x sem SafeMath
    contract Token {
        mapping(address => uint256) balances;
        function transfer(address to, uint256 amount) public {
            balances[msg.sender] -= amount;
            balances[to] += amount;
        }
    }
    """
    WIKI_RECOMMENDATION = (
        "Use SafeMath para Solidity < 0.8.0, ou atualize para >= 0.8.0 "
        "que tem overflow/underflow checks nativos."
    )

    def _detect(self):
        resultados = []

        for contrato in self.contracts:
            arquivo = contrato.source_mapping.filename.absolute
            if any(p in arquivo for p in IGNORAR):
                continue
            if getattr(contrato, "is_library", False):
                continue

            # Verifica versao do pragma diretamente no arquivo do contrato
            # (nao usa compilation_unit.pragma_directives que mistura deps)
            if not _arquivo_e_versao_antiga(arquivo):
                continue

            # Verifica uso de SafeMath no arquivo
            if _arquivo_usa_safemath(arquivo):
                continue

            # Conjunto de state variables nao-constantes
            vars_nao_constantes = {
                v for v in contrato.state_variables
                if not getattr(v, "is_constant", False)
            }

            if not vars_nao_constantes:
                continue

            for funcao in contrato.functions:
                if funcao.visibility in ("internal", "private"):
                    continue

                ops_encontradas = []
                for no in funcao.nodes:
                    for op in no.irs:
                        if isinstance(op, Binary) and op.type in OPS_SUSPEITAS:
                            vars_lidas = getattr(op, "read", [])

                            envolve_var_real = any(
                                v in vars_nao_constantes
                                for v in vars_lidas
                            )
                            escreve_var_real = any(
                                not getattr(v, "is_constant", False)
                                for v in no.state_variables_written
                            )

                            if envolve_var_real or escreve_var_real:
                                ops_encontradas.append((no, op.type.name))

                if ops_encontradas:
                    exemplos = list(dict.fromkeys(o[1] for o in ops_encontradas[:3]))
                    info = [
                        "Operacao aritmetica sem protecao em Solidity < 0.8.0: ",
                        funcao,
                        f"\n\t- Operacoes: {', '.join(exemplos)}",
                        f"\n\t- Ocorrencias: {len(ops_encontradas)}",
                        "\n\t- Risco: overflow/underflow silencioso\n",
                    ]
                    resultados.append(self.generate_result(info))

        return resultados
