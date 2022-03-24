#!/usr/bin/env python3
""" lift_tricore.py
The lifter module for tricore instructions.
"""
# pylint: disable=wildcard-import
# pylint: disable=unused-wildcard-import

from pyvex.lifting.util import *
from pyvex.lifting import register
from .abs_instr   import *
from .absb_instr  import *
from .b_instr     import *
from .bit_instr   import *
from .bo_instr    import *
from .bol_instr   import *
from .brc_instr   import *
from .brn_instr   import *
from .brr_instr   import *
from .rc_instr    import *
from .rcpw_instr  import *
from .rcr_instr   import *
from .rcrr_instr  import *
from .rcrw_instr  import *
from .rlc_instr   import *
from .rr_instr    import *
from .rr1_instr   import *
from .rr2_instr   import *
from .rrpw_instr  import *
from .rrr_instr   import *
from .rrr1_instr  import *
from .rrr2_instr  import *
from .rrrw_instr  import *
from .rrrr_instr  import *
from .sb_instr    import *
from .sbc_instr   import *
from .sbr_instr   import *
from .sbrn_instr  import *
from .sc_instr    import *
from .slr_instr   import *
from .slro_instr  import *
from .sr_instr    import *
from .src_instr   import *
from .sro_instr   import *
from .srr_instr   import *
from .srrs_instr  import *
from .ssr_instr   import *
from .ssro_instr  import *
from .sys_instr   import *


class LifterTRICORE(GymratLifter):
    """ Lifter class for Tricore. """
    instrs = [
        # ABS format ---------
        ABS_15_Instructions,
        ABS_E5_Instructions,
        ABS_LD_85_Instructions,
        ABS_LD_05_Instructions,
        ABS_LD_45_Instructions,
        ABS_LEA_Instruction,
        ABS_ST_A5_Instructions,
        ABS_ST_25_Instructions,
        ABS_ST_65_Instructions,

        # ABSB format ---------
        ABSB_ST_T_Inst,

        # BIT format ---------
        BIT_Acc_Logical_AND_Inst,
        BIT_Acc_Logical_OR_Inst,
        BIT_Acc_Shift_Inst_27,
        BIT_Acc_Shift_Inst_A7,
        BIT_Logical_Inst,
        BIT_Logical_07_Inst,
        BIT_Mov_Inst,

        # B format ---------
        B_CALL_Inst,
        B_CALLA_Inst,
        B_J_Inst,
        B_JA_Inst,
        B_JL_Inst,
        B_JLA_Inst,

        # BO format ---------
        BO_LD_09_Instructions,
        BO_LD_29_Instructions,
        BO_49_Instructions,
        BO_69_Instructions,
        BO_ST_89_Instructions,
        BO_ST_A9_Instructions,

        # BOL format ---------
        BOL_LD_A,
        BOL_LEA,
        BOL_LD_W,
        BOL_ST_W,

        # BRC format ---------
        BRC_Jump_Instructions_9f,
        BRC_Jump_Instructions_bf,
        BRC_Jump_Instructions_df,
        BRC_Jump_Instructions_ff,

        # BRN format ---------
        BRN_Jump_Inst,

        # BRR format ---------
        BRR_Jump_Instructions_1F,
        BRR_Jump_Instructions_3F,
        BRR_Jump_Instructions_5F,
        BRR_Jump_Instruczions_7F,
        BRR_Jump_Instructions_7D,
        BRR_Jump_Instructions_BD,
        BRR_Loop_Instructions_FD,

        # RC format  ---------
        RC_Instructions_53,
        RC_Instructions_8B,
        RC_Instructions_8F,
        RC_Instructions_AD,

        # RCPW format ---------
        RCPW_IMASK,
        RCPW_INSERT,

        # RCR format ---------
        RCR_Instructions_OP_AB,
        RCR_Instructions_OP_13,
        RCR_Instructions_OP_33,

        # RCRR format ---------
        RCRR_Instructions,

        # RCRW format ---------
        RCRW_IMASK,
        RCRW_INSERT,

        # RLC format ---------
        RLC_ADDI_Inst,
        RLC_ADDIH,
        RLC_ADDIH_A,
        RLC_MFCR,
        RLC_MOV,
        RLC_MOV_U,
        RLC_MOVH,
        RLC_MOVH_A,
        RLC_MTCR,

        # RR format ---------
        RR_ABS_Inst,
        RR_ABS_B_Inst,
        RR_ABS_H_Inst,
        RR_ABSDIF_Inst,
        RR_ABSDIF_B_Inst,
        RR_ABSDIF_H_Inst,
        RR_ABSDIFS_Inst,
        RR_ABSDIFS_H_Inst,
        RR_ABSS_Inst,
        RR_ABSS_H_Inst,
        RR_ADD_Inst,
        RR_ADD_A_Inst,
        RR_ADD_B_Inst,
        RR_ADD_H_Inst,
        RR_ADDC_Inst,
        RR_ADDS_Inst,
        RR_ADDS_H_Inst,
        RR_ADDS_HU_Inst,
        RR_ADDS_U_Inst,
        RR_ADDSC_A_Inst,
        RR_ADDSC_AT_Inst,
        RR_ADDX_Inst,
        RR_AND_Inst,
        RR_AND_EQ_Inst,
        RR_AND_GE_Inst,
        RR_AND_GE_U_Inst,
        RR_AND_LT_Inst,
        RR_AND_LT_U_Inst,
        RR_AND_NE_Inst,
        RR_ANDN_Inst,
        RR_BMERGE_Inst,
        RR_BSPLIT_Inst,
        RR_CALLI_Inst,
        RR_CLO_Inst,
        RR_CLO_H_Inst,
        RR_CLS_Inst,
        RR_CLS_H_Inst,
        RR_CLZ_Inst,
        RR_CLZ_H_Inst,
        RR_DVINIT_Inst,
        RR_DVINIT_B_Inst,
        RR_DVINIT_BU_Inst,
        RR_DVINIT_H_Inst,
        RR_DVINIT_HU_Inst,
        RR_DVINIT_U_Inst,
        RR_EQ_Inst,
        RR_EQ_A_Inst,
        RR_EQ_B_Inst,
        RR_EQ_H_Inst,
        RR_EQ_W_Inst,
        RR_EQANY_B_Inst,
        RR_EQANY_H_Inst,
        RR_EQZ_A_Inst,
        RR_GE_Inst,
        RR_GE_U_Inst,
        RR_GE_A_Inst,
        RR_JI_Inst,
        RR_JLI_Inst,
        RR_LT_Inst,
        RR_LT_U_Inst,
        RR_LT_A_Inst,
        RR_LT_B_Inst,
        RR_LT_BU_Inst,
        RR_LT_H_Inst,
        RR_LT_HU_Inst,
        RR_LT_W_Inst,
        RR_LT_WU_Inst,
        RR_MAX_Inst,
        RR_MAX_U_Inst,
        RR_MAX_B_Inst,
        RR_MAX_BU_Inst,
        RR_MAX_H_Inst,
        RR_MAX_HU_Inst,
        RR_MIN_Inst,
        RR_MIN_U_Inst,
        RR_MIN_B_Inst,
        RR_MIN_BU_Inst,
        RR_MIN_H_Inst,
        RR_MIN_HU_Inst,
        RR_MOV_Inst,
        RR_MOV_A_Inst,
        RR_MOV_AA_Inst,
        RR_MOV_D_Inst,
        RR_NAND_Inst,
        RR_NE_Inst,
        RR_NE_A_Inst,
        RR_NEZ_A_Inst,
        RR_NOR_Inst,
        RR_OR_Inst,
        RR_OR_EQ_Inst,
        RR_OR_GE_Inst,
        RR_OR_GE_U_Inst,
        RR_OR_LT_Inst,
        RR_OR_LT_U_Inst,
        RR_OR_NE_Inst,
        RR_ORN_Inst,
        RR_PARITY_Inst,
        RR_SAT_HU_Inst,
        RR_SH_Inst,
        RR_SH_EQ_Inst,
        RR_SH_GE_Inst,
        RR_SH_GE_U_Inst,
        RR_SH_LT_Inst,
        RR_SH_LT_U_Inst,
        RR_SH_H_Inst,
        RR_SH_NE_Inst,
        RR_SHA_Inst,
        RR_SHA_H_Inst,
        RR_SHAS_Inst,
        RR_SUB_Inst,
        RR_SUB_A_Inst,
        RR_SUB_B_Inst,
        RR_SUB_H_Inst,
        RR_SUBC_Inst,
        RR_SUBS_Inst,
        RR_SUBS_U_Inst,
        RR_SUBS_H_Inst,
        RR_SUBS_HU_Inst,
        RR_SUBX_Inst,
        RR_XNOR_Inst,
        RR_XOR_Inst,
        RR_XOR_EQ_Inst,
        RR_XOR_GE_Inst,
        RR_XOR_GE_U_Inst,
        RR_XOR_LT_Inst,
        RR_XOR_LT_U_Inst,
        RR_XOR_NE_Inst,

        # RR1 format ---------
        RR1_MUL_H_B3_Instructions,
        RR1_MUL_Q_93_Instructions,

        # RR2 format ---------
        RR2_MUL_Inst,
        RR2_MUL_6A_Inst,
        RR2_MULS_Inst,
        RR2_MUL_U_Inst,
        RR2_MULS_U_Inst,

        # RRPW format ---------
        RRPW_OP_37_Instructions,
        RRPW_OP_77_Instructions,

        # RRR format ---------
        RRR_CADD_Inst,
        RRR_CADDN_Inst,
        RRR_CSUB_Inst,
        RRR_CSUBN_Inst,
        RRR_DVADJ_Inst,
        RRR_DVSTEP_Inst,
        RRR_DVSTEP_U_Inst,
        RRR_SEL_Inst,
        RRR_SELN_Inst,

        # RRR1 format ---------
        RRR1_MADD_H_83_1A_Inst,
        RRR1_MADD_H_83_19_Inst,
        RRR1_MADD_H_83_18_Inst,
        RRR1_MADD_H_83_1B_Inst,
        RRR1_MADDS_H_83_3A_Inst,
        RRR1_MADDS_H_83_39_Inst,
        RRR1_MADDS_H_83_38_Inst,
        RRR1_MADDS_H_83_3B_Inst,
        RRR1_MADD_Q_43_02_Inst,
        RRR1_MADD_Q_43_1B_Inst,
        RRR1_MADD_Q_43_01_Inst,
        RRR1_MADD_Q_43_19_Inst,
        RRR1_MADD_Q_43_00_Inst,
        RRR1_MADD_Q_43_18_Inst,
        RRR1_MADD_Q_43_05_Inst,
        RRR1_MADD_Q_43_1D_Inst,
        RRR1_MADD_Q_43_04_Inst,
        RRR1_MADD_Q_43_1C_Inst,
        RRR1_MADDS_Q_43_22_Inst,
        RRR1_MADDS_Q_43_3B_Inst,
        RRR1_MADDS_Q_43_21_Inst,
        RRR1_MADDS_Q_43_39_Inst,
        RRR1_MADDS_Q_43_20_Inst,
        RRR1_MADDS_Q_43_38_Inst,
        RRR1_MADDS_Q_43_25_Inst,
        RRR1_MADDS_Q_43_3D_Inst,
        RRR1_MADDS_Q_43_24_Inst,
        RRR1_MADDS_Q_43_3C_Inst,
        RRR1_MADDM_H_83_1E_Inst,
        RRR1_MADDM_H_83_1D_Inst,
        RRR1_MADDM_H_83_1C_Inst,
        RRR1_MADDM_H_83_1F_Inst,
        RRR1_MADDMS_H_83_3E_Inst,
        RRR1_MADDMS_H_83_3D_Inst,
        RRR1_MADDMS_H_83_3C_Inst,
        RRR1_MADDMS_H_83_3F_Inst,
        RRR1_MADDR_H_83_0E_Inst,
        RRR1_MADDR_H_83_0D_Inst,
        RRR1_MADDR_H_83_0C_Inst,
        RRR1_MADDR_H_43_1E_Inst,
        RRR1_MADDR_H_83_0F_Inst,
        RRR1_MADDRS_H_83_2E_Inst,
        RRR1_MADDRS_H_83_2D_Inst,
        RRR1_MADDRS_H_83_2C_Inst,
        RRR1_MADDRS_H_43_3E_Inst,
        RRR1_MADDRS_H_83_2F_Inst,
        RRR1_MADDR_Q_43_07_Inst,
        RRR1_MADDR_Q_43_06_Inst,
        RRR1_MADDRS_Q_43_27_Inst,
        RRR1_MADDRS_Q_43_26_Inst,
        RRR1_MADDSU_H_C3_1A_Inst,
        RRR1_MADDSU_H_C3_19_Inst,
        RRR1_MADDSU_H_C3_18_Inst,
        RRR1_MADDSU_H_C3_1B_Inst,
        RRR1_MADDSUS_H_C3_3A_Inst,
        RRR1_MADDSUS_H_C3_39_Inst,
        RRR1_MADDSUS_H_C3_38_Inst,
        RRR1_MADDSUS_H_C3_3B_Inst,
        RRR1_MADDSUM_H_C3_1E_Inst,
        RRR1_MADDSUM_H_C3_1D_Inst,
        RRR1_MADDSUM_H_C3_1C_Inst,
        RRR1_MADDSUM_H_C3_1F_Inst,
        RRR1_MADDSUMS_H_C3_3E_Inst,
        RRR1_MADDSUMS_H_C3_3D_Inst,
        RRR1_MADDSUMS_H_C3_3C_Inst,
        RRR1_MADDSUMS_H_C3_3F_Inst,
        RRR1_MADDSUR_H_C3_0E_Inst,
        RRR1_MADDSUR_H_C3_0D_Inst,
        RRR1_MADDSUR_H_C3_0C_Inst,
        RRR1_MADDSUR_H_C3_0F_Inst,
        RRR1_MADDSURS_H_C3_2E_Inst,
        RRR1_MADDSURS_H_C3_2D_Inst,
        RRR1_MADDSURS_H_C3_2C_Inst,
        RRR1_MADDSURS_H_C3_2F_Inst,
        RRR1_MSUB_H_A3_1A_Inst,
        RRR1_MSUB_H_A3_19_Inst,
        RRR1_MSUB_H_A3_18_Inst,
        RRR1_MSUB_H_A3_1B_Inst,
        RRR1_MSUBS_H_A3_3A_Inst,
        RRR1_MSUBS_H_A3_39_Inst,
        RRR1_MSUBS_H_A3_38_Inst,
        RRR1_MSUBS_H_A3_3B_Inst,
        RRR1_MSUB_Q_63_02_Inst,
        RRR1_MSUB_Q_63_1B_Inst,
        RRR1_MSUB_Q_63_01_Inst,
        RRR1_MSUB_Q_63_19_Inst,
        RRR1_MSUB_Q_63_00_Inst,
        RRR1_MSUB_Q_63_18_Inst,
        RRR1_MSUB_Q_63_05_Inst,
        RRR1_MSUB_Q_63_1D_Inst,
        RRR1_MSUB_Q_63_04_Inst,
        RRR1_MSUB_Q_63_1C_Inst,
        RRR1_MSUBS_Q_63_22_Inst,
        RRR1_MSUBS_Q_63_3B_Inst,
        RRR1_MSUBS_Q_63_21_Inst,
        RRR1_MSUBS_Q_63_39_Inst,
        RRR1_MSUBS_Q_63_20_Inst,
        RRR1_MSUBS_Q_63_38_Inst,
        RRR1_MSUBS_Q_63_25_Inst,
        RRR1_MSUBS_Q_63_3D_Inst,
        RRR1_MSUBS_Q_63_24_Inst,
        RRR1_MSUBS_Q_63_3C_Inst,
        RRR1_MSUBAD_H_E3_1A_Inst,
        RRR1_MSUBAD_H_E3_19_Inst,
        RRR1_MSUBAD_H_E3_18_Inst,
        RRR1_MSUBAD_H_E3_1B_Inst,
        RRR1_MSUBADS_H_E3_3A_Inst,
        RRR1_MSUBADS_H_E3_39_Inst,
        RRR1_MSUBADS_H_E3_38_Inst,
        RRR1_MSUBADS_H_E3_3B_Inst,
        RRR1_MSUBADM_H_E3_1E_Inst,
        RRR1_MSUBADM_H_E3_1D_Inst,
        RRR1_MSUBADM_H_E3_1C_Inst,
        RRR1_MSUBADM_H_E3_1F_Inst,
        RRR1_MSUBADMS_H_E3_3E_Inst,
        RRR1_MSUBADMS_H_E3_3D_Inst,
        RRR1_MSUBADMS_H_E3_3C_Inst,
        RRR1_MSUBADMS_H_E3_3F_Inst,
        RRR1_MSUBADR_H_E3_0E_Inst,
        RRR1_MSUBADR_H_E3_0D_Inst,
        RRR1_MSUBADR_H_E3_0C_Inst,
        RRR1_MSUBADR_H_E3_0F_Inst,
        RRR1_MSUBADRS_H_E3_2E_Inst,
        RRR1_MSUBADRS_H_E3_2D_Inst,
        RRR1_MSUBADRS_H_E3_2C_Inst,
        RRR1_MSUBADRS_H_E3_2F_Inst,
        RRR1_MSUBM_H_A3_1E_Inst,
        RRR1_MSUBM_H_A3_1D_Inst,
        RRR1_MSUBM_H_A3_1C_Inst,
        RRR1_MSUBM_H_A3_1F_Inst,
        RRR1_MSUBMS_H_A3_3E_Inst,
        RRR1_MSUBMS_H_A3_3D_Inst,
        RRR1_MSUBMS_H_A3_3C_Inst,
        RRR1_MSUBMS_H_A3_3F_Inst,

        # RRR2 format ---------
        RRR2_MADD_32_Inst,
        RRR2_MADD_64_Inst,
        RRR2_MADD_U_64_Inst,
        RRR2_MADDS_32_Inst,
        RRR2_MADDS_64_Inst,
        RRR2_MADDS_U_32_Inst,
        RRR2_MADDS_U_64_Inst,
        RRR2_MSUB_32_Inst,
        RRR2_MSUB_64_Inst,
        RRR2_MSUBS_32_Inst,
        RRR2_MSUBS_64_Inst,
        RRR2_MSUB_U_64_Inst,
        RRR2_MSUBS_U_32_Inst,
        RRR2_MSUBS_U_64_Inst,

        # RRRW format ---------
        RRRW_Instructions,

        # RRRR format ---------
        RRRR_DEXTR_Inst,
        RRRR_EXTR_Inst,
        RRRR_EXTR_U_Inst,
        RRRR_INSERT_Inst,

        # SB format ---------
        SB_J_Inst,
        SB_JNZ_Inst,
        SB_JZ_Inst,

        # SBC format ---------
        SBC_JEQ_Inst,
        SBC_JNE_Inst,

        # SBR format ---------
        SBR_JEQ_Inst,
        SBR_JGEZ_Inst,
        SBR_JGTZ_Inst,
        SBR_JLEZ_Inst,
        SBR_JLTZ_Inst,
        SBR_JNE_Inst,
        SBR_JNZ_Inst,
        SBR_JNZ_A_Inst,
        SBR_JZ_Inst,
        SBR_JZ_A_Inst,
        SBR_LOOP_Inst,

        # SBRN format ---------
        SBRN_JZ_T_Inst,
        SBRN_JNZ_T_Inst,

        # SC format ---------
        SC_AND_Inst,
        SC_LD_A_Inst,
        SC_LD_W_Inst,
        SC_MOV_Inst,
        SC_OR_Inst,
        SC_ST_A_Inst,
        SC_SUB_A_Inst,
        SC_ST_A_Inst,
        SC_ST_W_Inst,

        # SLR format ---------
        SLR_LD_A_D4_Inst,
        SLR_LD_A_C4_Inst,
        SLR_LD_BU_14_Inst,
        SLR_LD_BU_04_Inst,
        SLR_LD_H_94_Inst,
        SLR_LD_H_84_Inst,
        SLR_LD_W_54_Inst,
        SLR_LD_W_44_Inst,

        # SLRO format ---------
        SLRO_LD_A_Inst,
        SLRO_LD_BU_Inst,
        SLRO_LD_H_Inst,
        SLRO_LD_W_Inst,

        # SR format ---------
        SR_DEBUG_Inst,
        SR_JI_Inst,
        SR_NOP_Inst,
        SR_NOT_Inst,
        SR_RET_Inst,
        SR_RFE_Inst,
        SR_RSUB_Inst,
        SR_SAT_HU_Inst,

        # SRC format ---------
        SRC_ADD_92_Inst,
        SRC_ADD_9A_Inst,
        SRC_ADD_C2_Inst,
        SRC_ADD_A_Inst,
        SRC_CADD_Inst,
        SRC_CADDN_Inst,
        SRC_CMOV_Inst,
        SRC_CMOVN_Inst,
        SRC_EQ_Inst,
        SRC_LT_Inst,
        SRC_MOV_Inst,
        SRC_MOV_A_Inst,
        SRC_SH_Inst,
        SRC_SHA_Inst,

        # SRO format ---------
        SRO_LD_A_Inst,
        SRO_LD_BU_Inst,
        SRO_LD_H_Inst,
        SRO_LD_W_Inst,
        SRO_ST_A_Inst,
        SRO_ST_B_Inst,
        SRO_ST_H_Inst,
        SRO_ST_W_Inst,

        # SRR format ---------
        SRR_ADD_12_Inst,
        SRR_ADD_1A_Inst,
        SRR_ADD_42_Inst,
        SRR_ADD_A_Inst,
        SRR_ADDS_Inst,
        SRR_AND_Inst,
        SRR_CMOV_Inst,
        SRR_CMOVN_Inst,
        SRR_EQ_Inst,
        SRR_LT_Inst,
        SRR_MOV_Inst,
        SRR_MOV_A_Inst,
        SRR_MOV_D_Inst,
        SRR_MOV_AA_Inst,
        SRR_MUL_Inst,
        SRR_OR_Inst,
        SRR_SUB_A2_Inst,
        SRR_SUB_52_Inst,
        SRR_SUB_5A_Inst,
        SRR_SUBS_Inst,
        SRR_XOR_Inst,

        # SRRS format ---------
        SRRS_ADDSC_A_Inst,

        # SSR format ---------
        SSR_ST_A_Inst,
        SSR_ST_A_E4_Inst,
        SSR_ST_B_Inst,
        SSR_ST_B_24_Inst,
        SSR_ST_H_Inst,
        SSR_ST_H_A4_Inst,
        SSR_ST_W_Inst,
        SSR_ST_W_64_Inst,

        # SSRO format ---------
        SSRO_ST_A_Inst,
        SSRO_ST_B_Inst,
        SSRO_ST_H_Inst,
        SSRO_ST_W_Inst,

        # SYS instructions ---------
        SYS_DEBUG_Inst,
        SYS_ISYNC_Inst,
        SYS_RSTV_Inst,
        SYS_NOP_Inst,
    ]

register(LifterTRICORE, 'TRICORE')
