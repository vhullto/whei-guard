# Pacote de detectores customizados do Whei Guard
from whei_rules.missing_access_control import MissingAccessControl
from whei_rules.reentrancy import Reentrancy
from whei_rules.tx_origin_auth import TxOriginAuth
from whei_rules.unchecked_send import UncheckedSend
from whei_rules.integer_overflow import IntegerOverflow
from whei_rules.uninitialized_proxy import UninitializedProxy
from whei_rules.oracle_manipulation import OracleManipulation
from whei_rules.flash_loan_attack import FlashLoanAttack

ALL_DETECTORS = [
    MissingAccessControl,
    Reentrancy,
    TxOriginAuth,
    UncheckedSend,
    IntegerOverflow,
    UninitializedProxy,
    OracleManipulation,
    FlashLoanAttack,
]
