from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification

# Caminhos ignorados
IGNORAR = (
    "test/", "tests/", "mock", "Mock", "lib/",
    "scripts/", ".t.sol", ".s.sol", "node_modules/",
)

# Nomes de funcoes que sao intencionalmente publicas por design
# e possuem protecao interna (nao precisam de modificador externo)
NOMES_PERMITIDOS = {
    # Padrao proxy upgradeable — protecao via require(initialized == false)
    "initialize", "initializev1", "initializev2", "initializev2_1",
    "initializev2_2", "initializev3", "initializev4", "initializev5",
    # ERC20/ERC721 padrao — funcoes publicas por especificacao
    "transfer", "transferfrom", "approve", "setapprovalforall",
    # ERC20 mint/burn controlados por roles (onlyMinter, onlyOwner via require interno)
    # nao incluimos aqui pois queremos flagrar os sem protecao alguma
}


def _tem_protecao_interna(funcao):
    """
    Verifica se a funcao possui protecao interna mesmo sem modificador externo.
    Casos comuns:
    1. Padrao proxy: require(_initializedVersion == N) ou require(!initialized)
    2. Funcao so pode ser chamada uma vez por design
    """
    for no in funcao.nodes:
        no_str = str(no).lower()
        # Verifica presenca de guards de inicializacao
        if any(guard in no_str for guard in (
            "initializedversion", "_initializedversion",
            "initialized", "initializer",
            "_initialized", "isinitialized",
        )):
            return True
    return False


def _e_funcao_initialize(funcao):
    """Retorna True se a funcao e uma funcao de inicializacao proxy."""
    nome = funcao.name.lower()
    return nome.startswith("initialize") or nome == "_disableinitializers"


class MissingAccessControl(AbstractDetector):

    ARGUMENT = "missing-access-control"
    HELP = "Funcao publica/externa modifica estado sem modificador de acesso"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://swcregistry.io/docs/SWC-105"
    WIKI_TITLE = "Missing Access Control"
    WIKI_DESCRIPTION = (
        "Uma funcao publica ou externa modifica variaveis de estado "
        "sem nenhum modificador de acesso (ex: onlyOwner). "
        "Isso permite que qualquer endereco altere o estado do contrato."
    )
    WIKI_EXPLOIT_SCENARIO = """
    contract Vulneravel {
        address public dono;
        function mudarDono(address novoDono) public {
            dono = novoDono;
        }
    }
    """
    WIKI_RECOMMENDATION = (
        "Aplique um modificador de controle de acesso (ex: onlyOwner) "
        "em todas as funcoes que modificam variaveis de estado sensiveis."
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
                if funcao.is_constructor or funcao.is_fallback or funcao.is_receive:
                    continue

                if funcao.visibility not in ("public", "external"):
                    continue

                if not funcao.state_variables_written:
                    continue

                if funcao.modifiers:
                    continue

                # Pula funcoes initialize com protecao interna (padrao proxy)
                if _e_funcao_initialize(funcao) and _tem_protecao_interna(funcao):
                    continue

                # Pula funcoes ERC20/ERC721 padrao (transfer, approve, etc)
                if funcao.name.lower() in NOMES_PERMITIDOS:
                    # Mas so pula se o contrato implementa ERC20/ERC721
                    nomes_heranca = {
                        c.name for c in getattr(contrato, "inheritance", [])
                    }
                    if any(erc in nomes_heranca for erc in (
                        "ERC20", "ERC721", "ERC1155", "IERC20", "IERC721",
                        "AbstractFiatToken", "FiatTokenV1",
                    )):
                        continue

                variaveis = ", ".join(v.name for v in funcao.state_variables_written)
                info = [
                    "Funcao sem controle de acesso detectada: ",
                    funcao,
                    f"\n\t- Visibilidade: {funcao.visibility}",
                    f"\n\t- Variaveis de estado escritas: {variaveis}",
                    "\n\t- Modificadores aplicados: nenhum\n",
                ]
                resultados.append(self.generate_result(info))

        return resultados
