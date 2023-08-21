use super::BITWISE_RATIO;
use super::CYCLE_HEIGHT;
use super::ECDSA_BUILTIN_RATIO;
use super::EC_OP_BUILTIN_RATIO;
use super::EC_OP_SCALAR_HEIGHT;
use super::MEMORY_STEP;
use super::PEDERSEN_BUILTIN_RATIO;
use super::POSEIDON_RATIO;
use super::POSEIDON_ROUNDS_FULL;
use super::PUBLIC_MEMORY_STEP;
use super::RANGE_CHECK_BUILTIN_PARTS;
use super::RANGE_CHECK_BUILTIN_RATIO;
use super::RANGE_CHECK_STEP;
use super::DILUTED_CHECK_N_BITS;
use super::DILUTED_CHECK_SPACING;
use super::ECDSA_SIG_CONFIG_ALPHA;
use super::ECDSA_SIG_CONFIG_BETA;
use crate::CairoAirConfig;
use crate::utils;
use crate::utils::compute_diluted_cumulative_value;
use crate::utils::map_into_fp_array;
use ark_ff::MontFp;
use ark_poly::EvaluationDomain;
use ark_poly::Radix2EvaluationDomain;
use binary::AirPublicInput;
use builtins::ecdsa;
use builtins::pedersen;
use builtins::poseidon;
use ministark::constraints::CompositionConstraint;
use ministark::constraints::CompositionItem;
use ministark::constraints::PeriodicColumn;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use ark_ff::Field;
use ministark::challenges::Challenges;
use ministark::constraints::AlgebraicItem;
use ministark::constraints::Constraint;
use ministark::constraints::ExecutionTraceColumn;
use ministark::constraints::Hint;
use ministark::constraints::VerifierChallenge;
use ministark::expression::Expr;
use ministark::hints::Hints;
use ministark::utils::FieldVariant;
use num_bigint::BigUint;
use num_traits::Pow;
use strum_macros::EnumIter;

const PEDERSEN_POINT_X: PeriodicColumn<'static, FieldVariant<Fp, Fp>> = {
    const INTERVAL_SIZE: usize = super::PEDERSEN_BUILTIN_RATIO * super::CYCLE_HEIGHT;
    const COEFFS: [FieldVariant<Fp, Fp>; 512] =
        map_into_fp_array(pedersen::periodic::HASH_POINTS_X_COEFFS);
    PeriodicColumn::new(&COEFFS, INTERVAL_SIZE)
};

const PEDERSEN_POINT_Y: PeriodicColumn<'static, FieldVariant<Fp, Fp>> = {
    const INTERVAL_SIZE: usize = super::PEDERSEN_BUILTIN_RATIO * super::CYCLE_HEIGHT;
    const COEFFS: [FieldVariant<Fp, Fp>; 512] =
        map_into_fp_array(pedersen::periodic::HASH_POINTS_Y_COEFFS);
    PeriodicColumn::new(&COEFFS, INTERVAL_SIZE)
};

const ECDSA_GENERATOR_POINT_X: PeriodicColumn<'static, FieldVariant<Fp, Fp>> = {
    const INTERVAL_SIZE: usize = super::ECDSA_BUILTIN_RATIO * super::CYCLE_HEIGHT;
    const COEFFS: [FieldVariant<Fp, Fp>; 256] =
        map_into_fp_array(ecdsa::periodic::GENERATOR_POINTS_X_COEFFS);
    PeriodicColumn::new(&COEFFS, INTERVAL_SIZE)
};

const ECDSA_GENERATOR_POINT_Y: PeriodicColumn<'static, FieldVariant<Fp, Fp>> = {
    const INTERVAL_SIZE: usize = super::ECDSA_BUILTIN_RATIO * super::CYCLE_HEIGHT;
    const COEFFS: [FieldVariant<Fp, Fp>; 256] =
        map_into_fp_array(ecdsa::periodic::GENERATOR_POINTS_Y_COEFFS);
    PeriodicColumn::new(&COEFFS, INTERVAL_SIZE)
};

const POSEIDON_POSEIDON_FULL_ROUND_KEY0: PeriodicColumn<'static, FieldVariant<Fp, Fp>> = {
    const INTERVAL_SIZE: usize = super::POSEIDON_RATIO * super::CYCLE_HEIGHT;
    const COEFFS: [FieldVariant<Fp, Fp>; 8] =
        map_into_fp_array(poseidon::periodic::FULL_ROUND_KEY_0_COEFFS);
    PeriodicColumn::new(&COEFFS, INTERVAL_SIZE)
};
const POSEIDON_POSEIDON_FULL_ROUND_KEY1: PeriodicColumn<'static, FieldVariant<Fp, Fp>> = {
    const INTERVAL_SIZE: usize = super::POSEIDON_RATIO * super::CYCLE_HEIGHT;
    const COEFFS: [FieldVariant<Fp, Fp>; 8] =
        map_into_fp_array(poseidon::periodic::FULL_ROUND_KEY_1_COEFFS);
    PeriodicColumn::new(&COEFFS, INTERVAL_SIZE)
};
const POSEIDON_POSEIDON_FULL_ROUND_KEY2: PeriodicColumn<'static, FieldVariant<Fp, Fp>> = {
    const INTERVAL_SIZE: usize = super::POSEIDON_RATIO * super::CYCLE_HEIGHT;
    const COEFFS: [FieldVariant<Fp, Fp>; 8] =
        map_into_fp_array(poseidon::periodic::FULL_ROUND_KEY_2_COEFFS);
    PeriodicColumn::new(&COEFFS, INTERVAL_SIZE)
};
const POSEIDON_POSEIDON_PARTIAL_ROUND_KEY0: PeriodicColumn<'static, FieldVariant<Fp, Fp>> = {
    const INTERVAL_SIZE: usize = super::POSEIDON_RATIO * super::CYCLE_HEIGHT;
    const COEFFS: [FieldVariant<Fp, Fp>; 64] =
        map_into_fp_array(poseidon::periodic::PARTIAL_ROUND_KEY_0_COEFFS);
    PeriodicColumn::new(&COEFFS, INTERVAL_SIZE)
};
const POSEIDON_POSEIDON_PARTIAL_ROUND_KEY1: PeriodicColumn<'static, FieldVariant<Fp, Fp>> = {
    const INTERVAL_SIZE: usize = super::POSEIDON_RATIO * super::CYCLE_HEIGHT;
    const COEFFS: [FieldVariant<Fp, Fp>; 32] =
        map_into_fp_array(poseidon::periodic::PARTIAL_ROUND_KEY_1_COEFFS);
    PeriodicColumn::new(&COEFFS, INTERVAL_SIZE)
};

pub struct AirConfig;

impl ministark::air::AirConfig for AirConfig {
    const NUM_BASE_COLUMNS: usize = 9;
    const NUM_EXTENSION_COLUMNS: usize = 1;
    type Fp = Fp;
    type Fq = Fp;
    type PublicInputs = AirPublicInput<Fp>;

    fn constraints(trace_len: usize) -> Vec<Constraint<FieldVariant<Fp, Fp>>> {
        use AlgebraicItem::*;
        use PublicInputHint::*;
        // TODO: figure out why this value
        let n = trace_len;
        let trace_domain = Radix2EvaluationDomain::<Fp>::new(n).unwrap();
        let g = trace_domain.group_gen();
        assert!(n >= CYCLE_HEIGHT, "must be a multiple of cycle height");
        // TODO: might be good to have more trace size assertions for builtins etc.
        // for example ECDSA requires a minimum trace size of 2048 for this layout.
        // NOTE: All this stuff is taken care by the runner of if you run properly
        // i.e correct params
        let x = Expr::from(X);
        let one = Expr::from(Constant(FieldVariant::Fp(Fp::ONE)));
        let two = Expr::from(Constant(FieldVariant::Fp(Fp::from(2u32))));
        let four = Expr::from(Constant(FieldVariant::Fp(Fp::from(4u32))));
        let offset_size = Expr::from(Constant(FieldVariant::Fp(Fp::from(2u32.pow(16)))));
        let half_offset_size = Expr::from(Constant(FieldVariant::Fp(Fp::from(2u32.pow(15)))));

        // cpu/decode/flag_op1_base_op0_0
        let cpu_decode_flag_op1_base_op0_0 =
            &one - (Flag::Op1Imm.curr() + Flag::Op1Ap.curr() + Flag::Op1Fp.curr());
        // cpu/decode/flag_res_op1_0
        let cpu_decode_flag_res_op1_0 =
            &one - (Flag::ResAdd.curr() + Flag::ResMul.curr() + Flag::PcJnz.curr());
        // cpu/decode/flag_pc_update_regular_0
        let cpu_decode_flag_pc_update_regular_0 =
            &one - (Flag::PcJumpAbs.curr() + Flag::PcJumpRel.curr() + Flag::PcJnz.curr());
        // cpu/decode/fp_update_regular_0
        let cpu_decode_fp_update_regular_0 =
            &one - (Flag::OpcodeCall.curr() + Flag::OpcodeRet.curr());

        // NOTE: npc_reg_0 = pc + instruction_size
        // NOTE: instruction_size = fOP1_IMM + 1
        let npc_reg_0 = Npc::Pc.curr() + Flag::Op1Imm.curr() + &one;

        let memory_address_diff_0 = Mem::Address.next() - Mem::Address.curr();

        let rc16_diff_0 = RangeCheck::Ordered.next() - RangeCheck::Ordered.curr();

        // TODO: builtins
        let pedersen_hash0_ec_subset_sum_b0 =
            Pedersen::Suffix.curr() - (Pedersen::Suffix.next() + Pedersen::Suffix.next());
        let pedersen_hash0_ec_subset_sum_b0_negate = &one - &pedersen_hash0_ec_subset_sum_b0;
        let rc_builtin_value0_0 = RangeCheckBuiltin::Rc16Component.offset(0);
        let rc_builtin_value1_0 =
            &rc_builtin_value0_0 * &offset_size + RangeCheckBuiltin::Rc16Component.offset(1);
        let rc_builtin_value2_0 =
            &rc_builtin_value1_0 * &offset_size + RangeCheckBuiltin::Rc16Component.offset(2);
        let rc_builtin_value3_0 =
            &rc_builtin_value2_0 * &offset_size + RangeCheckBuiltin::Rc16Component.offset(3);
        let rc_builtin_value4_0 =
            &rc_builtin_value3_0 * &offset_size + RangeCheckBuiltin::Rc16Component.offset(4);
        let rc_builtin_value5_0 =
            &rc_builtin_value4_0 * &offset_size + RangeCheckBuiltin::Rc16Component.offset(5);
        let rc_builtin_value6_0 =
            &rc_builtin_value5_0 * &offset_size + RangeCheckBuiltin::Rc16Component.offset(6);
        let rc_builtin_value7_0 =
            &rc_builtin_value6_0 * &offset_size + RangeCheckBuiltin::Rc16Component.offset(7);
        let ecdsa_sig0_doubling_key_x_squared =
            Ecdsa::PubkeyDoublingX.curr() * Ecdsa::PubkeyDoublingX.curr();
        let ecdsa_sig0_exponentiate_generator_b0 = Ecdsa::MessageSuffix.curr()
            - (Ecdsa::MessageSuffix.next() + Ecdsa::MessageSuffix.next());
        let ecdsa_sig0_exponentiate_generator_b0_neg = &one - &ecdsa_sig0_exponentiate_generator_b0;
        let ecdsa_sig0_exponentiate_key_b0 =
            Ecdsa::RSuffix.curr() - (Ecdsa::RSuffix.next() + Ecdsa::RSuffix.next());
        let ecdsa_sig0_exponentiate_key_b0_neg = &one - &ecdsa_sig0_exponentiate_key_b0;

        // bits 0->127 (inclusive) of a bitwise number
        let bitwise_sum_var_0_0 = Bitwise::Bits16Chunk0Offset0.curr()
            + Bitwise::Bits16Chunk0Offset1.curr() * (&two).pow(1)
            + Bitwise::Bits16Chunk0Offset2.curr() * (&two).pow(2)
            + Bitwise::Bits16Chunk0Offset3.curr() * (&two).pow(3)
            + Bitwise::Bits16Chunk1Offset0.curr() * (&two).pow(64)
            + Bitwise::Bits16Chunk1Offset1.curr() * (&two).pow(65)
            + Bitwise::Bits16Chunk1Offset2.curr() * (&two).pow(66)
            + Bitwise::Bits16Chunk1Offset3.curr() * (&two).pow(67);
        // bits 128->255 (inclusive) of a bitwise number
        let bitwise_sum_var_8_0 = Bitwise::Bits16Chunk2Offset0.curr() * (&two).pow(128)
            + Bitwise::Bits16Chunk2Offset1.curr() * (&two).pow(129)
            + Bitwise::Bits16Chunk2Offset2.curr() * (&two).pow(130)
            + Bitwise::Bits16Chunk2Offset3.curr() * (&two).pow(131)
            + Bitwise::Bits16Chunk3Offset0.curr() * (&two).pow(192)
            + Bitwise::Bits16Chunk3Offset1.curr() * (&two).pow(193)
            + Bitwise::Bits16Chunk3Offset2.curr() * (&two).pow(194)
            + Bitwise::Bits16Chunk3Offset3.curr() * (&two).pow(195);

        let ec_op_doubling_q_x_squared_0 = EcOp::QDoublingX.curr() * EcOp::QDoublingX.curr();
        let ec_op_ec_subset_sum_bit_0 =
            EcOp::MSuffix.curr() - (EcOp::MSuffix.next() + EcOp::MSuffix.next());
        let ec_op_ec_subset_sum_bit_0_neg = &one - &ec_op_ec_subset_sum_bit_0;

        let poseidon_poseidon_full_rounds_state0_cubed_0 =
            Poseidon::FullRoundsState0.offset(0) * Poseidon::FullRoundsState0Squared.offset(0);
        let poseidon_poseidon_full_rounds_state1_cubed_0 =
            Poseidon::FullRoundsState1.offset(0) * Poseidon::FullRoundsState1Squared.offset(0);
        let poseidon_poseidon_full_rounds_state2_cubed_0 =
            Poseidon::FullRoundsState2.offset(0) * Poseidon::FullRoundsState2Squared.offset(0);
        let poseidon_poseidon_full_rounds_state0_cubed_7 =
            Poseidon::FullRoundsState0.offset(7) * Poseidon::FullRoundsState0Squared.offset(7);
        let poseidon_poseidon_full_rounds_state1_cubed_7 =
            Poseidon::FullRoundsState1.offset(7) * Poseidon::FullRoundsState1Squared.offset(7);
        let poseidon_poseidon_full_rounds_state2_cubed_7 =
            Poseidon::FullRoundsState2.offset(7) * Poseidon::FullRoundsState2Squared.offset(7);
        let poseidon_poseidon_full_rounds_state0_cubed_3 =
            Poseidon::FullRoundsState0.offset(3) * Poseidon::FullRoundsState0Squared.offset(3);
        let poseidon_poseidon_full_rounds_state1_cubed_3 =
            Poseidon::FullRoundsState1.offset(3) * Poseidon::FullRoundsState1Squared.offset(3);
        let poseidon_poseidon_full_rounds_state2_cubed_3 =
            Poseidon::FullRoundsState2.offset(3) * Poseidon::FullRoundsState2Squared.offset(3);
        let poseidon_poseidon_partial_rounds_state0_cubed_0 = Poseidon::PartialRoundsState0
            .offset(0)
            * Poseidon::PartialRoundsState0Squared.offset(0);
        let poseidon_poseidon_partial_rounds_state0_cubed_1 = Poseidon::PartialRoundsState0
            .offset(1)
            * Poseidon::PartialRoundsState0Squared.offset(1);
        let poseidon_poseidon_partial_rounds_state0_cubed_2 = Poseidon::PartialRoundsState0
            .offset(2)
            * Poseidon::PartialRoundsState0Squared.offset(2);
        let poseidon_poseidon_partial_rounds_state1_cubed_0 = Poseidon::PartialRoundsState1
            .offset(0)
            * Poseidon::PartialRoundsState1Squared.offset(0);
        let poseidon_poseidon_partial_rounds_state1_cubed_1 = Poseidon::PartialRoundsState1
            .offset(1)
            * Poseidon::PartialRoundsState1Squared.offset(1);
        let poseidon_poseidon_partial_rounds_state1_cubed_2 = Poseidon::PartialRoundsState1
            .offset(2)
            * Poseidon::PartialRoundsState1Squared.offset(2);
        let poseidon_poseidon_partial_rounds_state1_cubed_19 = Poseidon::PartialRoundsState1
            .offset(19)
            * Poseidon::PartialRoundsState1Squared.offset(19);
        let poseidon_poseidon_partial_rounds_state1_cubed_20 = Poseidon::PartialRoundsState1
            .offset(20)
            * Poseidon::PartialRoundsState1Squared.offset(20);
        let poseidon_poseidon_partial_rounds_state1_cubed_21 = Poseidon::PartialRoundsState1
            .offset(21)
            * Poseidon::PartialRoundsState1Squared.offset(21);

        // example for trace length n=64
        // =============================
        // x^(n/16)                 = (x - ω_0)(x - ω_16)(x - ω_32)(x - ω_48)
        // x^(n/16) - c             = (x - c*ω_0)(x - c*ω_16)(x - c*ω_32)(x - c*ω_48)
        // x^(n/16) - ω^(n/16)      = (x - ω_1)(x - ω_17)(x - ω_33)(x - )
        // x^(n/16) - ω^(n/16)^(15) = (x - ω_15)(x - ω_31)(x - ω_47)(x - ω_6ω_493)
        let flag0_offset =
            FieldVariant::Fp(g.pow([(Flag::Zero as usize * n / CYCLE_HEIGHT) as u64]));
        let flag0_zerofier = X.pow(n / CYCLE_HEIGHT) - Constant(flag0_offset);
        let every_row_zerofier = X.pow(n) - &one;
        let every_row_zerofier_inv = &one / every_row_zerofier;
        let flags_zerofier_inv = &flag0_zerofier * &every_row_zerofier_inv;

        // check decoded flag values are 0 or 1
        // NOTE: This expression is a bit confusing. The zerofier forces this constraint
        // to apply in all rows of the trace therefore it applies to all flags (not just
        // DstReg). Funnily enough any flag here would work (it just wouldn't be SHARP
        // compatible).
        let cpu_decode_opcode_rc_b =
            (Flag::DstReg.curr() * Flag::DstReg.curr() - Flag::DstReg.curr()) * &flags_zerofier_inv;

        // The first word of each instruction:
        // ┌─────────────────────────────────────────────────────────────────────────┐
        // │                     off_dst (biased representation)                     │
        // ├─────────────────────────────────────────────────────────────────────────┤
        // │                     off_op0 (biased representation)                     │
        // ├─────────────────────────────────────────────────────────────────────────┤
        // │                     off_op1 (biased representation)                     │
        // ├─────┬─────┬───────┬───────┬───────────┬────────┬───────────────────┬────┤
        // │ dst │ op0 │  op1  │  res  │    pc     │   ap   │      opcode       │ 0  │
        // │ reg │ reg │  src  │ logic │  update   │ update │                   │    │
        // ├─────┼─────┼───┬───┼───┬───┼───┬───┬───┼───┬────┼────┬────┬────┬────┼────┤
        // │  0  │  1  │ 2 │ 3 │ 4 │ 5 │ 6 │ 7 │ 8 │ 9 │ 10 │ 11 │ 12 │ 13 │ 14 │ 15 │
        // └─────┴─────┴───┴───┴───┴───┴───┴───┴───┴───┴────┴────┴────┴────┴────┴────┘
        let whole_flag_prefix = Expr::from(Trace(0, 0));
        // NOTE: Forces the `0` flag prefix to =0 in every cycle.
        let cpu_decode_opcode_rc_zero = &whole_flag_prefix / flag0_zerofier;

        // force constraint to apply every 16 trace rows (every cairo cycle)
        // e.g. (x - ω_0)(x - ω_16)(x - ω_32)(x - ω_48) for n=64
        let all_cycles_zerofier = X.pow(n / CYCLE_HEIGHT) - &one;
        let all_cycles_zerofier_inv = &one / all_cycles_zerofier;
        let cpu_decode_opcode_rc_input = (Npc::Instruction.curr()
            - (((&whole_flag_prefix * &offset_size + RangeCheck::OffOp1.curr()) * &offset_size
                + RangeCheck::OffOp0.curr())
                * &offset_size
                + RangeCheck::OffDst.curr()))
            * &all_cycles_zerofier_inv;

        // constraint for the Op1Src flag group - forces vals 000, 100, 010 or 001
        let cpu_decode_flag_op1_base_op0_bit = (&cpu_decode_flag_op1_base_op0_0
            * &cpu_decode_flag_op1_base_op0_0
            - &cpu_decode_flag_op1_base_op0_0)
            * &all_cycles_zerofier_inv;

        // forces only one or none of ResAdd, ResMul or PcJnz to be 1
        // TODO: Why the F is PcJnz in here? Res flag group is only bit 5 and 6
        // NOTE: looks like it's a handy optimization to calculate next_fp and next_ap
        let cpu_decode_flag_res_op1_bit = (&cpu_decode_flag_res_op1_0 * &cpu_decode_flag_res_op1_0
            - &cpu_decode_flag_res_op1_0)
            * &all_cycles_zerofier_inv;

        // constraint forces PcUpdate flag to be 000, 100, 010 or 001
        let cpu_decode_flag_pc_update_regular_bit = (&cpu_decode_flag_pc_update_regular_0
            * &cpu_decode_flag_pc_update_regular_0
            - &cpu_decode_flag_pc_update_regular_0)
            * &all_cycles_zerofier_inv;

        // forces max only OpcodeRet or OpcodeAssertEq to be 1
        // TODO: why OpcodeCall not included? that would make whole flag group
        let cpu_decode_fp_update_regular_bit = (&cpu_decode_fp_update_regular_0
            * &cpu_decode_fp_update_regular_0
            - &cpu_decode_fp_update_regular_0)
            * &all_cycles_zerofier_inv;

        // cpu/operands/mem_dst_addr
        // NOTE: Pseudo code from cairo whitepaper
        // ```
        // if dst_reg == 0:
        //     dst = m(ap + offdst)
        // else:
        //     dst = m(fp + offdst)
        // ```
        // NOTE: Trace(5, 8) dest mem address
        let cpu_operands_mem_dst_addr = (Npc::MemDstAddr.curr() + &half_offset_size
            - (Flag::DstReg.curr() * Auxiliary::Fp.curr()
                + (&one - Flag::DstReg.curr()) * Auxiliary::Ap.curr()
                + RangeCheck::OffDst.curr()))
            * &all_cycles_zerofier_inv;

        // whitepaper pseudocode
        // ```
        // # Compute op0.
        // if op0_reg == 0:
        //     op0 = m(-->>ap + offop0<<--)
        // else:
        //     op0 = m(-->>fp + offop0<<--)
        // ```
        // NOTE: StarkEx contracts as: cpu_operands_mem0_addr
        let cpu_operands_mem_op0_addr = (Npc::MemOp0Addr.curr() + &half_offset_size
            - (Flag::Op0Reg.curr() * Auxiliary::Fp.curr()
                + (&one - Flag::Op0Reg.curr()) * Auxiliary::Ap.curr()
                + RangeCheck::OffOp0.curr()))
            * &all_cycles_zerofier_inv;

        // NOTE: StarkEx contracts as: cpu_operands_mem1_addr
        let cpu_operands_mem_op1_addr = (Npc::MemOp1Addr.curr() + &half_offset_size
            - (Flag::Op1Imm.curr() * Npc::Pc.curr()
                + Flag::Op1Ap.curr() * Auxiliary::Ap.curr()
                + Flag::Op1Fp.curr() * Auxiliary::Fp.curr()
                + &cpu_decode_flag_op1_base_op0_0 * Npc::MemOp0.curr()
                + RangeCheck::OffOp1.curr()))
            * &all_cycles_zerofier_inv;

        // op1 * op0
        // NOTE: starkex cpu/operands/ops_mul
        let cpu_operands_ops_mul = (Auxiliary::Op0MulOp1.curr()
            - Npc::MemOp0.curr() * Npc::MemOp1.curr())
            * &all_cycles_zerofier_inv;

        // From cairo whitepaper
        // ```
        // # Compute res.
        // if pc_update == 4:
        //     if res_logic == 0 && opcode == 0 && ap_update != 1:
        //         res = Unused
        //     else:
        //         Undefined Behavior
        // else if pc_update = 0, 1 or 2:
        //     switch res_logic:
        //         case 0: res = op1
        //         case 1: res = op0 + op1
        //         case 2: res = op0 * op1
        //         default: Undefined Behavior
        // else: Undefined Behavior
        // ```
        // NOTE: this constraint only handles:
        // ```
        // else if pc_update = 0, 1 or 2:
        //   switch res_logic:
        //     case 0: res = op1
        //     case 1: res = op0 + op1
        //     case 2: res = op0 * op1
        // ```
        let cpu_operands_res = ((&one - Flag::PcJnz.curr()) * Auxiliary::Res.curr()
            - (Flag::ResAdd.curr() * (Npc::MemOp0.curr() + Npc::MemOp1.curr())
                + Flag::ResMul.curr() * Auxiliary::Op0MulOp1.curr()
                + &cpu_decode_flag_res_op1_0 * Npc::MemOp1.curr()))
            * &all_cycles_zerofier_inv;

        // example for trace length n=64
        // =============================
        // all_cycles_zerofier              = (x - ω_0)(x - ω_16)(x - ω_32)(x - ω_48)
        // X - ω^(16*(n/16 - 1))            = x - ω^n/w^16 = x - 1/w_16 = x - w_48
        // (X - w_48) / all_cycles_zerofier = (x - ω_0)(x - ω_16)(x - ω_32)
        let last_cycle_zerofier = X - Constant(FieldVariant::Fp(
            g.pow([(CYCLE_HEIGHT * (n / CYCLE_HEIGHT - 1)) as u64]),
        ));
        let last_cycle_zerofier_inv = &one / &last_cycle_zerofier;
        let all_cycles_except_last_zerofier_inv = &last_cycle_zerofier * &all_cycles_zerofier_inv;

        // Updating the program counter
        // ============================
        // This is not as straight forward as the other constraints. Read section 9.5
        // Updating pc to understand.

        // from whitepaper `t0 = fPC_JNZ * dst`
        let cpu_update_registers_update_pc_tmp0 = (Auxiliary::Tmp0.curr()
            - Flag::PcJnz.curr() * Npc::MemDst.curr())
            * &all_cycles_except_last_zerofier_inv;

        // From the whitepaper "To verify that we make a regular update if dst = 0, we
        // need an auxiliary variable, v (to fill the trace in the case dst != 0, set v
        // = dst^(−1)): `fPC_JNZ * (dst * v − 1) * (next_pc − (pc + instruction_size)) =
        // 0` NOTE: if fPC_JNZ=1 then `res` is "unused" and repurposed as our
        // temporary variable `v`. The value assigned to v is `dst^(−1)`.
        // NOTE: `t1 = t0 * v`
        let cpu_update_registers_update_pc_tmp1 = (Auxiliary::Tmp1.curr()
            - Auxiliary::Tmp0.curr() * Auxiliary::Res.curr())
            * &all_cycles_except_last_zerofier_inv;

        // There are two constraints here bundled in one. The first is `t0 * (next_pc −
        // (pc + op1)) = 0` (ensures if dst != 0 a relative jump is made) and the second
        // is `(1−fPC_JNZ) * next_pc - (regular_update * (pc + instruction_size) +
        // fPC_JUMP_ABS * res + fPC_JUMP_REL * (pc + res)) = 0` (handles update except
        // for jnz). Note that due to the flag group constraints for PcUpdate if jnz=1
        // then the second constraint is trivially 0=0 and if jnz=0 then the first
        // constraint is trivially 0=0. For this reason we can bundle these constraints
        // into one.
        // TODO: fix padding bug
        let cpu_update_registers_update_pc_pc_cond_negative = ((&one - Flag::PcJnz.curr())
            * Npc::Pc.next()
            + Auxiliary::Tmp0.curr() * (Npc::Pc.next() - (Npc::Pc.curr() + Npc::MemOp1.curr()))
            - (&cpu_decode_flag_pc_update_regular_0 * &npc_reg_0
                + Flag::PcJumpAbs.curr() * Auxiliary::Res.curr()
                + Flag::PcJumpRel.curr() * (Npc::Pc.curr() + Auxiliary::Res.curr())))
            * &all_cycles_except_last_zerofier_inv;

        // ensure `if dst == 0: pc + instruction_size == next_pc`
        let cpu_update_registers_update_pc_pc_cond_positive =
            ((Auxiliary::Tmp1.curr() - Flag::PcJnz.curr()) * (Npc::Pc.next() - npc_reg_0))
                * &all_cycles_except_last_zerofier_inv;

        // Updating the allocation pointer
        // ===============================
        // TODO: seems fishy don't see how `next_ap = ap + fAP_ADD · res + fAP_ADD1 · 1
        // + fOPCODE_CALL · 2` meets the pseudo code in the whitepaper
        // Ok, it does kinda make sense. move the `opcode == 1` statement inside and
        // move the switch to the outside and it's more clear.
        let cpu_update_registers_update_ap_ap_update = (Auxiliary::Ap.next()
            - (Auxiliary::Ap.curr()
                + Flag::ApAdd.curr() * Auxiliary::Res.curr()
                + Flag::ApAdd1.curr()
                + Flag::OpcodeCall.curr() * &two))
            * &all_cycles_except_last_zerofier_inv;

        // Updating the frame pointer
        // ==========================
        // This handles all fp update except the `op0 == pc + instruction_size`, `res =
        // dst` and `dst == fp` assertions.
        // TODO: fix padding bug
        let cpu_update_registers_update_fp_fp_update = (Auxiliary::Fp.next()
            - (&cpu_decode_fp_update_regular_0 * Auxiliary::Fp.curr()
                + Flag::OpcodeRet.curr() * Npc::MemDst.curr()
                + Flag::OpcodeCall.curr() * (Auxiliary::Ap.curr() + &two)))
            * &all_cycles_except_last_zerofier_inv;

        // push registers to memory (see section 8.4 in the whitepaper).
        // These are essentially the assertions for assert `op0 == pc +
        // instruction_size` and `assert dst == fp`.
        let cpu_opcodes_call_push_fp = (Flag::OpcodeCall.curr()
            * (Npc::MemDst.curr() - Auxiliary::Fp.curr()))
            * &all_cycles_zerofier_inv;
        let cpu_opcodes_call_push_pc = (Flag::OpcodeCall.curr()
            * (Npc::MemOp0.curr() - (Npc::Pc.curr() + Flag::Op1Imm.curr() + &one)))
            * &all_cycles_zerofier_inv;

        // make sure all offsets are valid for the call opcode
        // ===================================================
        // checks `if opcode == OpcodeCall: assert off_dst = 2^15`
        // this is supplementary to the constraints above because
        // offsets are in the range [-2^15, 2^15) encoded using
        // biased representation
        let cpu_opcodes_call_off0 = (Flag::OpcodeCall.curr()
            * (RangeCheck::OffDst.curr() - &half_offset_size))
            * &all_cycles_zerofier_inv;
        // checks `if opcode == OpcodeCall: assert off_op0 = 2^15 + 1`
        // TODO: why +1?
        let cpu_opcodes_call_off1 = (Flag::OpcodeCall.curr()
            * (RangeCheck::OffOp0.curr() - (&half_offset_size + &one)))
            * &all_cycles_zerofier_inv;
        // TODO: I don't understand this one - Flag::OpcodeCall.curr() is 0 or 1. Why
        // not just replace `Flag::OpcodeCall.curr() + Flag::OpcodeCall.curr() +
        // &one + &one` with `4`
        let cpu_opcodes_call_flags = (Flag::OpcodeCall.curr()
            * (Flag::OpcodeCall.curr() + Flag::OpcodeCall.curr() + &one + &one
                - (Flag::DstReg.curr() + Flag::Op0Reg.curr() + &four)))
            * &all_cycles_zerofier_inv;
        // checks `if opcode == OpcodeRet: assert off_dst = 2^15 - 2`
        // TODO: why -2 🤯? Instruction size?
        let cpu_opcodes_ret_off0 = (Flag::OpcodeRet.curr()
            * (RangeCheck::OffDst.curr() + &two - &half_offset_size))
            * &all_cycles_zerofier_inv;
        // checks `if opcode == OpcodeRet: assert off_op1 = 2^15 - 1`
        // TODO: why -1?
        let cpu_opcodes_ret_off2 = (Flag::OpcodeRet.curr()
            * (RangeCheck::OffOp1.curr() + &one - &half_offset_size))
            * &all_cycles_zerofier_inv;
        // checks `if OpcodeRet: assert PcJumpAbs=1, DstReg=1, Op1Fp=1, ResLogic=0`
        let cpu_opcodes_ret_flags = (Flag::OpcodeRet.curr()
            * (Flag::PcJumpAbs.curr()
                + Flag::DstReg.curr()
                + Flag::Op1Fp.curr()
                + &cpu_decode_flag_res_op1_0
                - &four))
            * &all_cycles_zerofier_inv;
        // handles the "assert equal" instruction. Represents this pseudo code from the
        // whitepaper `assert res = dst`.
        let cpu_opcodes_assert_eq_assert_eq = (Flag::OpcodeAssertEq.curr()
            * (Npc::MemDst.curr() - Auxiliary::Res.curr()))
            * &all_cycles_zerofier_inv;

        let first_row_zerofier = &x - &one;
        let first_row_zerofier_inv = &one / first_row_zerofier;

        // boundary constraint expression for initial registers
        let initial_ap = (Auxiliary::Ap.curr() - InitialAp.hint()) * &first_row_zerofier_inv;
        let initial_fp = (Auxiliary::Fp.curr() - InitialAp.hint()) * &first_row_zerofier_inv;
        let initial_pc = (Npc::Pc.curr() - InitialPc.hint()) * &first_row_zerofier_inv;

        // boundary constraint expression for final registers
        let final_ap = (Auxiliary::Ap.curr() - FinalAp.hint()) * &last_cycle_zerofier_inv;
        let final_fp = (Auxiliary::Fp.curr() - InitialAp.hint()) * &last_cycle_zerofier_inv;
        let final_pc = (Npc::Pc.curr() - FinalPc.hint()) * &last_cycle_zerofier_inv;

        // examples for trace length n=8
        // =============================
        // x^(n/2) - 1             = (x - ω_0)(x - ω_2)(x - ω_4)(x - ω_6)
        // x - ω^(2*(n/2 - 1))     = x - ω^n/w^2 = x - 1/w_2 = x - w_6
        // (x - w_6) / x^(n/2) - 1 = (x - ω_0)(x - ω_2)(x - ω_4)
        let every_second_row_zerofier = X.pow(n / 2) - &one;
        let second_last_row_zerofier =
            X - Constant(FieldVariant::Fp(g.pow([2 * (n as u64 / 2 - 1)])));
        let every_second_row_except_last_zerofier_inv =
            &second_last_row_zerofier / &every_second_row_zerofier;

        // Memory access constraints
        // =========================
        // All these constraints make more sense once you understand how the permutation
        // column is calculated (look at get_ordered_memory_accesses()). Sections 9.8
        // and 9.7 of the Cairo paper justify these constraints.
        // memory permutation boundary constraint
        let memory_multi_column_perm_perm_init0 = ((MemoryPermutation::Z.challenge()
            - (Mem::Address.curr() + MemoryPermutation::A.challenge() * Mem::Value.curr()))
            * Permutation::Memory.curr()
            + Npc::Pc.curr()
            + MemoryPermutation::A.challenge() * Npc::Instruction.curr()
            - MemoryPermutation::Z.challenge())
            * &first_row_zerofier_inv;
        // memory permutation transition constraint
        // NOTE: memory entries are stacked in the trace like so:
        // ┌─────┬───────────┬─────┐
        // │ ... │    ...    │ ... │
        // ├─────┼───────────┼─────┤
        // │ ... │ address 0 │ ... │
        // ├─────┼───────────┼─────┤
        // │ ... │  value 0  │ ... │
        // ├─────┼───────────┼─────┤
        // │ ... │ address 1 │ ... │
        // ├─────┼───────────┼─────┤
        // │ ... │  value 1  │ ... │
        // ├─────┼───────────┼─────┤
        // │ ... │    ...    │ ... │
        // └─────┴───────────┴─────┘
        let memory_multi_column_perm_perm_step0 = ((MemoryPermutation::Z.challenge()
            - (Mem::Address.next() + MemoryPermutation::A.challenge() * Mem::Value.next()))
            * Permutation::Memory.next()
            - (MemoryPermutation::Z.challenge()
                - (Npc::PubMemAddr.curr()
                    + MemoryPermutation::A.challenge() * Npc::PubMemVal.curr()))
                * Permutation::Memory.curr())
            * &every_second_row_except_last_zerofier_inv;
        // Check the last permutation value to verify public memory
        let memory_multi_column_perm_perm_last =
            (Permutation::Memory.curr() - MemoryQuotient.hint()) / &second_last_row_zerofier;
        // Constraint expression for memory/diff_is_bit
        // checks the address doesn't change or increases by 1
        // "Continuity" constraint in cairo whitepaper 9.7.2
        let memory_diff_is_bit = (&memory_address_diff_0 * &memory_address_diff_0
            - &memory_address_diff_0)
            * &every_second_row_except_last_zerofier_inv;
        // if the address stays the same then the value stays the same
        // "Single-valued" constraint in cairo whitepaper 9.7.2.
        // cairo uses nondeterministic read-only memory so if the address is the same
        // the value should also stay the same.
        let memory_is_func = ((&memory_address_diff_0 - &one)
            * (Mem::Value.curr() - Mem::Value.next()))
            * &every_second_row_except_last_zerofier_inv;
        // boundary condition stating the first memory address == 1
        let memory_initial_addr = (Mem::Address.curr() - &one) * &first_row_zerofier_inv;
        // applies every 8 rows
        let every_eighth_row_zerofier = X.pow(n / 8) - &one;
        let every_eighth_row_zerofier_inv = &one / &every_eighth_row_zerofier;
        // Read cairo whitepaper section 9.8 as to why the public memory cells are 0.
        // The high level is that the way public memory works is that the prover is
        // forced (with these constraints) to exclude the public memory from one of
        // the permutation products. This means the running permutation column
        // terminates with more-or-less the permutation of just the public input. The
        // verifier can relatively cheaply calculate this terminal. The constraint for
        // this terminal is `memory_multi_column_perm_perm_last`.
        let public_memory_addr_zero = Npc::PubMemAddr.curr() * &every_eighth_row_zerofier_inv;
        let public_memory_value_zero = Npc::PubMemVal.curr() * &every_eighth_row_zerofier_inv;

        // examples for trace length n=16
        // =====================================
        // x^(n/4) - 1              = (x - ω_0)(x - ω_4)(x - ω_8)(x - ω_12)
        // x - ω^(4*(n/4 - 1))      = x - ω^n/w^4 = x - 1/w_4 = x - w_12
        // (x - w_12) / x^(n/4) - 1 = (x - ω_0)(x - ω_4)(x - ω_8)
        let every_fourth_row_zerofier_inv = &one / (X.pow(n / 4) - &one);
        let fourth_last_row_zerofier =
            X - Constant(FieldVariant::Fp(g.pow([4 * (n as u64 / 4 - 1)])));
        let every_fourth_row_except_last_zerofier_inv =
            &fourth_last_row_zerofier * &every_fourth_row_zerofier_inv;

        // Range check constraints
        // =======================
        // Look at memory to understand the general approach to permutation.
        // More info in section 9.9 of the Cairo paper.
        let rc16_perm_init0 = ((RangeCheckPermutation::Z.challenge() - RangeCheck::Ordered.curr())
            * Permutation::RangeCheck.curr()
            + RangeCheck::OffDst.curr()
            - RangeCheckPermutation::Z.challenge())
            * &first_row_zerofier_inv;
        let rc16_perm_step0 = ((RangeCheckPermutation::Z.challenge() - RangeCheck::Ordered.next())
            * Permutation::RangeCheck.next()
            - (RangeCheckPermutation::Z.challenge() - RangeCheck::OffOp1.curr())
                * Permutation::RangeCheck.curr())
            * &every_fourth_row_except_last_zerofier_inv;
        let rc16_perm_last =
            (Permutation::RangeCheck.curr() - RangeCheckProduct.hint()) / &fourth_last_row_zerofier;
        // Check the value increases by 0 or 1
        let rc16_diff_is_bit = (&rc16_diff_0 * &rc16_diff_0 - &rc16_diff_0)
            * &every_fourth_row_except_last_zerofier_inv;
        // Prover sends the minimim and maximum as a public input.
        // Verifier checks the RC min and max fall within [0, 2^16).
        let rc16_minimum =
            (RangeCheck::Ordered.curr() - RangeCheckMin.hint()) * &first_row_zerofier_inv;
        let rc16_maximum =
            (RangeCheck::Ordered.curr() - RangeCheckMax.hint()) / &fourth_last_row_zerofier;

        // Diluted Check constraints
        // =========================
        // A "dilution" is spreading out of the bits in a number.
        // Dilutions have two parameters (1) the number of bits they operate on and
        // (2) the spread of each bit. For example the the dilution of binary
        // digit 1111 to 0001000100010001 operates on 4 bits with a spread of 4.
        let diluted_check_permutation_init0 = ((DilutedCheckPermutation::Z.challenge()
            - DilutedCheck::Ordered.curr())
            * Permutation::DilutedCheck.curr()
            + DilutedCheck::Unordered.curr()
            - DilutedCheckPermutation::Z.challenge())
            * &first_row_zerofier_inv;

        // Diluted checks operate every 8 rows (twice per cycle)
        let zerofier_8th_last_row = X - Constant(FieldVariant::Fp(g.pow([8 * (n as u64 / 8 - 1)])));
        let zerofier_8th_last_row_inv = &one / &zerofier_8th_last_row;
        let every_8_row_zerofier = X.pow(n / 8) - &one;
        let every_8_row_zerofier_inv = &one / &every_8_row_zerofier;
        let every_8_rows_except_last_zerofier_inv =
            &zerofier_8th_last_row * &every_8_row_zerofier_inv;

        // we have an out-of-order and in-order list of diluted values for this layout
        // (starknet). We want to check each list is a permutation of one another
        let diluted_check_permutation_step0 = ((DilutedCheckPermutation::Z.challenge()
            - DilutedCheck::Ordered.next())
            * Permutation::DilutedCheck.next()
            - (DilutedCheckPermutation::Z.challenge() - DilutedCheck::Unordered.next())
                * Permutation::DilutedCheck.curr())
            * &every_8_rows_except_last_zerofier_inv;
        let diluted_check_permutation_last = (Permutation::DilutedCheck.curr()
            - DilutedCheckProduct.hint())
            * &zerofier_8th_last_row_inv;

        // Initial aggregate value should be =1
        let diluted_check_init = (DilutedCheck::Aggregate.curr() - &one) * &first_row_zerofier_inv;

        // Check first, in-order, diluted value
        let diluted_check_first_element =
            (DilutedCheck::Ordered.curr() - DilutedCheckFirst.hint()) * &first_row_zerofier_inv;

        // TODO: add more docs
        // `diluted_diff` is related to `u` in `compute_diluted_cumulative_value`
        // Note that if there is no difference between the current and next ordered
        // diluted values then `diluted_diff == 0` and the previous aggregate value is
        // copied over
        let diluted_diff = DilutedCheck::Ordered.next() - DilutedCheck::Ordered.curr();
        let diluted_check_step = (DilutedCheck::Aggregate.next()
            - (DilutedCheck::Aggregate.curr()
                * (&one + DilutedCheckAggregation::Z.challenge() * &diluted_diff)
                + DilutedCheckAggregation::A.challenge() * &diluted_diff * diluted_diff))
            * &every_8_rows_except_last_zerofier_inv;

        // Check the last cumulative value.
        // NOTE: This can be calculated efficiently by the verifier.
        let diluted_check_last = (DilutedCheck::Aggregate.curr()
            - DilutedCheckCumulativeValue.hint())
            * &zerofier_8th_last_row_inv;

        // Pedersen builtin
        // ================
        // Each hash spans across 256 rows - that's one hash per 16 cairo steps.
        let every_256_row_zerofier_inv = &one / (X.pow(n / 256) - &one);

        // These first few pedersen constraints check that the number is in the range
        // ```text
        //  100000000000000000000000000000000000000000000000000000010001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001
        //  ^                                                       ^    ^
        // 251                                                     196  191
        // ```

        // Use knowledge of bits 251,196,192 to determine if there is a unique unpacking
        let pedersen_hash0_ec_subset_sub_bit_unpacking_last_one_is_zero =
            (Pedersen::Bit251AndBit196AndBit192.curr()
                * (Pedersen::Suffix.curr() - (Pedersen::Suffix.next() + Pedersen::Suffix.next())))
                * &every_256_row_zerofier_inv;
        let shift191 = Constant(FieldVariant::Fp(Fp::from(BigUint::from(2u32).pow(191u32))));
        let pedersen_hash0_ec_subset_sub_bit_unpacking_zeros_between_ones =
            (Pedersen::Bit251AndBit196AndBit192.curr()
                * (Pedersen::Suffix.offset(1) - Pedersen::Suffix.offset(192) * shift191))
                * &every_256_row_zerofier_inv;
        let pedersen_hash0_ec_subset_sum_bit_unpacking_cumulative_bit192 =
            (Pedersen::Bit251AndBit196AndBit192.curr()
                - Pedersen::Bit251AndBit196.curr()
                    * (Pedersen::Suffix.offset(192)
                        - (Pedersen::Suffix.offset(193) + Pedersen::Suffix.offset(193))))
                * &every_256_row_zerofier_inv;
        let shift3 = Constant(FieldVariant::Fp(Fp::from(BigUint::from(2u32).pow(3u32))));
        let pedersen_hash0_ec_subset_sum_bit_unpacking_zeroes_between_ones192 =
            (Pedersen::Bit251AndBit196.curr()
                * (Pedersen::Suffix.offset(193) - Pedersen::Suffix.offset(196) * shift3))
                * &every_256_row_zerofier_inv;
        let pedersen_hash0_ec_subset_sum_bit_unpacking_cumulative_bit196 =
            (Pedersen::Bit251AndBit196.curr()
                - (Pedersen::Suffix.offset(251)
                    - (Pedersen::Suffix.offset(252) + Pedersen::Suffix.offset(252)))
                    * (Pedersen::Suffix.offset(196)
                        - (Pedersen::Suffix.offset(197) + Pedersen::Suffix.offset(197))))
                * &every_256_row_zerofier_inv;
        // TODO: docs
        let shift54 = Constant(FieldVariant::Fp(Fp::from(BigUint::from(2u32).pow(54u32))));
        let pedersen_hash0_ec_subset_sum_bit_unpacking_zeroes_between_ones196 = ((Pedersen::Suffix
            .offset(251)
            - (Pedersen::Suffix.offset(252) + Pedersen::Suffix.offset(252)))
            * (Pedersen::Suffix.offset(197) - Pedersen::Suffix.offset(251) * shift54))
            * &every_256_row_zerofier_inv;

        // example for trace length n=512
        // =============================
        // x^(n/256) - ω^(255*n/256)    = (x-ω^255)(x-ω^511)
        // (x-ω^255)(x-ω^511) / (X^n-1) = 1/(x-ω^0)..(x-ω^254)(x-ω^256)..(x-ω^510)
        // vanishes on groups of 256 consecutive rows except the last row in each group
        // TODO: come up with better names for these
        let pedersen_transition_zerofier_inv = (X.pow(n / 256)
            - Constant(FieldVariant::Fp(g.pow([(255 * n / 256) as u64]))))
            * &every_row_zerofier_inv;

        // Constraint operated on groups of 256 rows.
        // Each row shifts a large number to the right. E.g.
        // ```text
        // row0:   10101...10001 <- constraint applied
        // row1:    1010...11000 <- constraint applied
        // ...               ... <- constraint applied
        // row255:             0 <- constraint disabled
        // row256: 11101...10001 <- constraint applied
        // row257:  1110...01000 <- constraint applied
        // ...               ... <- constraint applied
        // row511:             0 <- constraint disabled
        // ...               ...
        // ```
        let pedersen_hash0_ec_subset_sum_booleanity_test = (&pedersen_hash0_ec_subset_sum_b0
            * (&pedersen_hash0_ec_subset_sum_b0 - &one))
            * &pedersen_transition_zerofier_inv;

        // example for trace length n=512
        // =============================
        // x^(n/256) - ω^(63*n/64)      = x^(n/256) - ω^(252*n/256)
        // x^(n/256) - ω^(255*n/256)    = (x-ω^252)(x-ω^508)
        // (x-ω^255)(x-ω^511) / (X^n-1) = 1/(x-ω^0)..(x-ω^254)(x-ω^256)..(x-ω^510)
        // vanishes on the 252nd row of every 256 rows
        let pedersen_zero_suffix_zerofier_inv =
            &one / (X.pow(n / 256) - Constant(FieldVariant::Fp(g.pow([(63 * n / 64) as u64]))));

        // Note that with cairo's default field each element is 252 bits.
        // Therefore we are decomposing 252 bit numbers to do pedersen hash.
        // Since we have a column that right shifts a number each row we check that the
        // suffix of row 252 (of every 256 row group) equals 0 e.g.
        // ```text
        // row0:   10101...10001
        // row1:    1010...11000
        // ...               ...
        // row250:            10
        // row251:             1
        // row252:             0 <- check zero
        // row253:             0
        // row254:             0
        // row255:             0
        // row256: 11101...10001
        // row257:  1110...01000
        // ...               ...
        // row506:            11
        // row507:             1
        // row508:             0 <- check zero
        // row509:             0
        // ...               ...
        // ```
        // <https://docs.starkware.co/starkex/crypto/pedersen-hash-function.html>
        let pedersen_hash0_ec_subset_sum_bit_extraction_end =
            Pedersen::Suffix.curr() * &pedersen_zero_suffix_zerofier_inv;

        // TODO: is this constraint even needed?
        // check suffix in row 255 of each 256 row group is zero
        let pedersen_hash0_ec_subset_sum_zeros_tail = Pedersen::Suffix.curr()
            * (&one / (X.pow(n / 256) - Constant(FieldVariant::Fp(g.pow([255 * n as u64 / 256])))));

        // Create a periodic table comprising of the constant Pedersen points we need to
        // add together. The columns of this table are represented by polynomials that
        // evaluate to the `i`th row when evaluated on the `i`th power of the 512th root
        // of unity. e.g.
        //
        // let:
        // - `[P]_x` denotes the x-coordinate of an elliptic-curve point P
        // - P_1, P_2, P_3, P_4 be fixed elliptic curve points that parameterize the
        //   Pedersen hash function
        //
        // then our point table is:
        // ┌───────────┬────────────────────┬────────────────────┐
        // │     X     │       F_x(X)       │       F_y(X)       │
        // ├───────────┼────────────────────┼────────────────────┤
        // │    ω^0    │   [P_1 * 2^0]_x    │   [P_1 * 2^0]_y    │
        // ├───────────┼────────────────────┼────────────────────┤
        // │    ω^1    │   [P_1 * 2^1]_x    │   [P_1 * 2^1]_y    │
        // ├───────────┼────────────────────┼────────────────────┤
        // │    ...    │         ...        │         ...        │
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^247   │  [P_1 * 2^247]_x   │  [P_1 * 2^247]_y   │
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^248   │   [P_2 * 2^0]_x    │   [P_2 * 2^0]_y    │
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^249   │   [P_2 * 2^1]_x    │   [P_2 * 2^1]_y    │
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^250   │   [P_2 * 2^2]_x    │   [P_2 * 2^2]_y    │
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^251   │   [P_2 * 2^3]_x    │   [P_2 * 2^3]_y    │
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^252   │   [P_2 * 2^3]_x    │   [P_2 * 2^3]_y    │<- unused copy of prev
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^253   │   [P_2 * 2^3]_x    │   [P_2 * 2^3]_y    │<- unused copy of prev
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^254   │   [P_2 * 2^3]_x    │   [P_2 * 2^3]_y    │<- unused copy of prev
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^255   │   [P_2 * 2^3]_x    │   [P_2 * 2^3]_y    │<- unused copy of prev
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^256   │   [P_3 * 2^0]_x    │   [P_3 * 2^0]_y    │
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^257   │   [P_3 * 2^1]_x    │   [P_3 * 2^1]_y    │
        // ├───────────┼────────────────────┼────────────────────┤
        // │    ...    │         ...        │         ...        │
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^503   │  [P_3 * 2^247]_x   │  [P_3 * 2^247]_y   │
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^504   │   [P_4 * 2^0]_x    │   [P_4 * 2^0]_y    │
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^505   │   [P_4 * 2^1]_x    │   [P_4 * 2^1]_y    │
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^506   │   [P_4 * 2^2]_x    │   [P_4 * 2^2]_y    │
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^507   │   [P_4 * 2^3]_x    │   [P_4 * 2^3]_y    │
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^508   │   [P_4 * 2^3]_x    │   [P_4 * 2^3]_y    │<- unused copy of prev
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^509   │   [P_4 * 2^3]_x    │   [P_4 * 2^3]_y    │<- unused copy of prev
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^510   │   [P_4 * 2^3]_x    │   [P_4 * 2^3]_y    │<- unused copy of prev
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^511   │   [P_4 * 2^3]_x    │   [P_4 * 2^3]_y    │<- unused copy of prev
        // └───────────┴────────────────────┴────────────────────┘
        let pedersen_point_x = Expr::from(Periodic(PEDERSEN_POINT_X));
        let pedersen_point_y = Expr::from(Periodic(PEDERSEN_POINT_Y));

        // let `P = (Px, Py)` be the point to be added (see above)
        // let `Q = (Qx, Qy)` be the partial result
        // note that the slope = dy/dx with dy = Qy - Py, dx = Qx - Px
        // this constraint is equivalent to: bit * dy = dy/dx * dx
        // NOTE: slope is 0 if bit is 0
        let pedersen_hash0_ec_subset_sum_add_points_slope = (&pedersen_hash0_ec_subset_sum_b0
            * (Pedersen::PartialSumY.curr() - &pedersen_point_y)
            - Pedersen::Slope.curr() * (Pedersen::PartialSumX.curr() - &pedersen_point_x))
            * &pedersen_transition_zerofier_inv;

        // These two constraint check classic short Weierstrass curve point addition.
        // Constraint is equivalent to:
        // - `Qx_next = m^2 - Qx - Px, m = dy/dx`
        // - `Qy_next = m*(Qx - Qx_next) - Qy, m = dy/dx`
        let pedersen_hash0_ec_subset_sum_add_points_x = (Pedersen::Slope.curr()
            * Pedersen::Slope.curr()
            - &pedersen_hash0_ec_subset_sum_b0
                * (Pedersen::PartialSumX.curr()
                    + &pedersen_point_x
                    + Pedersen::PartialSumX.next()))
            * &pedersen_transition_zerofier_inv;
        let pedersen_hash0_ec_subset_sum_add_points_y = (&pedersen_hash0_ec_subset_sum_b0
            * (Pedersen::PartialSumY.curr() + Pedersen::PartialSumY.next())
            - Pedersen::Slope.curr()
                * (Pedersen::PartialSumX.curr() - Pedersen::PartialSumX.next()))
            * &pedersen_transition_zerofier_inv;
        // if the bit is 0 then just copy the previous point
        let pedersen_hash0_ec_subset_sum_copy_point_x = (&pedersen_hash0_ec_subset_sum_b0_negate
            * (Pedersen::PartialSumX.next() - Pedersen::PartialSumX.curr()))
            * &pedersen_transition_zerofier_inv;
        let pedersen_hash0_ec_subset_sum_copy_point_y = (&pedersen_hash0_ec_subset_sum_b0_negate
            * (Pedersen::PartialSumY.next() - Pedersen::PartialSumY.curr()))
            * &pedersen_transition_zerofier_inv;

        // example for trace length n=1024
        // =============================
        // x^(n/512) - ω^(n/2)                = x^(n/512) - ω^(256*n/512)
        // x^(n/512) - ω^(256*n/512)          = (x-ω^256)(x-ω^768)
        // x^(n/256) - 1                      = (x-ω_0)(x-ω_256)(x-ω_512)(x-ω_768)
        // (x-ω^256)(x-ω^768) / (x^(n/256)-1) = 1/(x-ω_0)(x-ω_512)
        // 1/(x^(n/512) - 1)                  = 1/(x-ω_0)(x-ω_512)
        // NOTE: By using `(x-ω^256)(x-ω^768) / (x^(n/256)-1)` rather than
        // `1/(x^(n/512) - 1)` we save an inversion operation since 1 / (x^(n/256)-1)
        // has been calculated already and as a result of how constraints are
        // evaluated it will be cached.
        // TODO: check all zerofiers are being multiplied or divided correctly
        let every_512_row_zerofier_inv = (X.pow(n / 512)
            - Constant(FieldVariant::Fp(g.pow([n as u64 / 2]))))
            * &every_256_row_zerofier_inv;

        // A single pedersen hash `H(a, b)` is computed every 512 cycles.
        // The constraints for each hash is split in two consecutive 256 row groups.
        // - 1st group computes `e0 = P0 + a_low * P1 + a_high * P2`
        // - 2nd group computes `e1 = e0 + B_low * P3 + B_high * P4`
        // We make sure the initial value of each group is loaded correctly:
        // - 1st group we check P0 (the shift point) is the first partial sum
        // - 2nd group we check e0 (processed `a`) is the first partial sum
        let pedersen_hash0_copy_point_x = (Pedersen::PartialSumX.offset(256)
            - Pedersen::PartialSumX.offset(255))
            * &every_512_row_zerofier_inv;
        let pedersen_hash0_copy_point_y = (Pedersen::PartialSumY.offset(256)
            - Pedersen::PartialSumY.offset(255))
            * &every_512_row_zerofier_inv;
        // TODO: introducing a new zerofier that's equivalent to the
        // previous one? double check every_512_row_zerofier
        let every_512_row_zerofier = X.pow(n / 512) - Constant(FieldVariant::Fp(Fp::ONE));
        let every_512_row_zerofier_inv = &one / &every_512_row_zerofier;
        let shift_point = pedersen::constants::P0;
        let pedersen_hash0_init_x = (Pedersen::PartialSumX.curr()
            - Constant(FieldVariant::Fp(shift_point.x)))
            * &every_512_row_zerofier_inv;
        let pedersen_hash0_init_y = (Pedersen::PartialSumY.curr()
            - Constant(FieldVariant::Fp(shift_point.y)))
            * &every_512_row_zerofier_inv;

        // TODO: fix naming
        let zerofier_512th_last_row =
            X - Constant(FieldVariant::Fp(g.pow([512 * (n as u64 / 512 - 1)])));
        let every_512_rows_except_last_zerofier =
            &zerofier_512th_last_row * &every_512_row_zerofier_inv;

        // Link Input0 into the memory pool.
        let pedersen_input0_value0 =
            (Npc::PedersenInput0Val.curr() - Pedersen::Suffix.curr()) * &every_512_row_zerofier_inv;
        // Input0's next address should be the address directly
        // after the output address of the previous hash
        let pedersen_input0_addr = (Npc::PedersenInput0Addr.next()
            - (Npc::PedersenOutputAddr.curr() + &one))
            * &every_512_rows_except_last_zerofier;
        // Ensure the first pedersen address matches the hint
        let pedersen_init_addr =
            (Npc::PedersenInput0Addr.curr() - InitialPedersenAddr.hint()) * &first_row_zerofier_inv;

        // Link Input1 into the memory pool.
        // Input1's address should be the address directly after input0's address
        let pedersen_input1_value0 = (Npc::PedersenInput1Val.curr() - Pedersen::Suffix.offset(256))
            * &every_512_row_zerofier_inv;
        let pedersen_input1_addr = (Npc::PedersenInput1Addr.curr()
            - (Npc::PedersenInput0Addr.curr() + &one))
            * &every_512_row_zerofier_inv;

        // Link pedersen output into the memory pool.
        // Output's address should be the address directly after input1's address.
        let pedersen_output_value0 = (Npc::PedersenOutputVal.curr()
            - Pedersen::PartialSumX.offset(511))
            * &every_512_row_zerofier_inv;
        let pedersen_output_addr = (Npc::PedersenOutputAddr.curr()
            - (Npc::PedersenInput1Addr.curr() + &one))
            * &every_512_row_zerofier_inv;

        // 128bit Range check builtin
        // ===================

        // TODO: fix naming
        let zerofier_256th_last_row =
            X - Constant(FieldVariant::Fp(g.pow([256 * (n as u64 / 256 - 1)])));
        let every_256_rows_except_last_zerofier =
            &zerofier_256th_last_row * &every_256_row_zerofier_inv;

        // Hook up range check with the memory pool
        let rc_builtin_value =
            (rc_builtin_value7_0 - Npc::RangeCheck128Val.curr()) * &every_256_row_zerofier_inv;
        let rc_builtin_addr_step = (Npc::RangeCheck128Addr.next()
            - (Npc::RangeCheck128Addr.curr() + &one))
            * &every_256_rows_except_last_zerofier;

        let rc_builtin_init_addr =
            (Npc::RangeCheck128Addr.curr() - InitialRcAddr.hint()) * &first_row_zerofier_inv;

        // Signature constraints for ECDSA
        // ===============================

        // example for trace length n=32768
        // ================================
        // x^(n/16384) - ω^(255*n/256)     = x^(n/16384) - ω^(16320*n/16384)
        // x^(n/16384) - ω^(16320*n/16384) = (x-ω^16320)(x-ω^32704)
        //                                 = (x-ω^(64*255))(x-ω^(64*511))
        let every_64_row_zerofier = X.pow(n / 64) - &one;
        let every_64_row_zerofier_inv = &one / every_64_row_zerofier;
        // vanishes on every 64 steps except the 255th of every 256
        let ec_op_transition_zerofier_inv = (X.pow(n / 16384)
            - Constant(FieldVariant::Fp(g.pow([(255 * n / 256) as u64]))))
            * &every_64_row_zerofier_inv;

        // ecdsa/signature0/doubling_key/slope
        // TODO: figure out

        // These constraint maps to the curve point doubling equation:
        // https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Point_doubling
        // ```text
        // curve eq: y^2 = x^3 + a*x + b
        // P = (x_p, y_p)
        // R = P + P = (x_r, x_y)
        // slope = (3*x_p^2 + a) / (2*y_p)
        // R_x = slope^2 - 2*x_p
        // R_y = slope*(x_p - x_r) - y_p
        // ```
        let ecdsa_sig_config_alpha = Constant(FieldVariant::Fp(ECDSA_SIG_CONFIG_ALPHA));
        // This constraint is checking `0 = (3*x_p^2 + a) - 2*y_p * slope`
        let ecdsa_signature0_doubling_key_slope = (&ecdsa_sig0_doubling_key_x_squared
            + &ecdsa_sig0_doubling_key_x_squared
            + &ecdsa_sig0_doubling_key_x_squared
            + ecdsa_sig_config_alpha
            - (Ecdsa::PubkeyDoublingY.curr() + Ecdsa::PubkeyDoublingY.curr())
                * Ecdsa::PubkeyDoublingSlope.curr())
            * &ec_op_transition_zerofier_inv;
        // This constraint checks `R_x = slope^2 - 2*x_p` => `0 = slope^2 - 2*x_p - R_x`
        let ecdsa_signature0_doubling_key_x = (Ecdsa::PubkeyDoublingSlope.curr()
            * Ecdsa::PubkeyDoublingSlope.curr()
            - (Ecdsa::PubkeyDoublingX.curr()
                + Ecdsa::PubkeyDoublingX.curr()
                + Ecdsa::PubkeyDoublingX.next()))
            * &ec_op_transition_zerofier_inv;
        // This constraint checks `R_y = slope*(x_p - x_r) - y_p` =>
        // `0 = y_p + R_y - slope*(x_p - x_r)`.
        let ecdsa_signature0_doubling_key_y = (Ecdsa::PubkeyDoublingY.curr()
            + Ecdsa::PubkeyDoublingY.next()
            - Ecdsa::PubkeyDoublingSlope.curr()
                * (Ecdsa::PubkeyDoublingX.curr() - Ecdsa::PubkeyDoublingX.next()))
            * &ec_op_transition_zerofier_inv;

        // example for trace length n=65536
        // ================================
        // x^(n/32768) - ω^(255*n/256)     = x^(n/32768) - ω^(32640*n/32768)
        // x^(n/32768) - ω^(32640*n/32768) = (x-ω^32640)(x-ω^65408)
        //                                 = (x-ω^(128*255))(x-ω^(128*511))
        let every_128_row_zerofier = X.pow(n / 128) - &one;
        // vanishes on every 128 steps except the 255th of every 256
        let ecdsa_transition_zerofier_inv = (X.pow(n / 32768)
            - Constant(FieldVariant::Fp(g.pow([(255 * n / 256) as u64]))))
            / &every_128_row_zerofier;

        // Constraint operates 256 times in steps of 128 rows
        // Each row shifts the message hash to the right. E.g.
        // ```text
        // row(128 * 0 + 38):     10101...10001 <- constraint applied
        // row(128 * 1 + 38):      1010...11000 <- constraint applied
        // ...                                  <- constraint applied
        // row(128 * 255 + 38):               0 <- constraint disabled
        // row(128 * 256 + 38):   11101...10001 <- constraint applied
        // row(128 * 257 + 38):    1110...01000 <- constraint applied
        // ...                                  <- constraint applied
        // row(128 * 511 + 38):               0 <- constraint disabled
        // ...
        // ```
        let ecdsa_signature0_exponentiate_generator_booleanity_test =
            (&ecdsa_sig0_exponentiate_generator_b0
                * (&ecdsa_sig0_exponentiate_generator_b0 - &one))
                * &ecdsa_transition_zerofier_inv;

        // example for trace length n=65536
        // =============================
        // x^(n/32768) - ω^(251*n/256)     = x^(n/32768) - ω^(32128*n/32768)
        // x^(n/32768) - ω^(32128*n/32768) = (x-ω^(32768*0+32128))(x-ω^(32768*1+32128))
        // vanishes on the 251st row of every 256 rows
        let ecdsa_zero_suffix_zerofier =
            X.pow(n / 32768) - Constant(FieldVariant::Fp(g.pow([(251 * n / 256) as u64])));

        // Note that with cairo's default field each element is 252 bits.
        // For Cairo's ECDSA we allow the message hash to be a 251 bit number.
        // Since we have a column that right shifts a number each row we check that the
        // suffix of row 251 (of every 256 row group) equals 0 e.g.
        // ```text
        // row(128 * 0 + 38):   10101...10001 <- NOTE: 1st ECDSA instance start
        // row(128 * 1 + 38):    1010...11000
        // ...
        // row(128 * 249 + 38):            10
        // row(128 * 250 + 38):             1
        // row(128 * 251 + 38):             0 <- check zero
        // row(128 * 252 + 38):             0
        // row(128 * 253 + 38):             0
        // row(128 * 254 + 38):             0
        // row(128 * 255 + 38):             0
        // row(128 * 256 + 38): 11101...10001 <- NOTE: 2nd ECDSA instance start
        // row(128 * 257 + 38):  1110...01000
        // ...
        // row(128 * 505 + 38):            11
        // row(128 * 506 + 38):             1
        // row(128 * 507 + 38):             0 <- check zero
        // row(128 * 508 + 38):             0
        // ...
        // ```
        let ecdsa_signature0_exponentiate_generator_bit_extraction_end =
            Ecdsa::MessageSuffix.curr() / &ecdsa_zero_suffix_zerofier;

        // TODO: is this constraint even needed?
        // check suffix in row 255 of each 256 row group is zero
        let ecdsa_signature0_exponentiate_generator_zeros_tail = Ecdsa::MessageSuffix.curr()
            / (X.pow(n / 32768) - Constant(FieldVariant::Fp(g.pow([255 * n as u64 / 256]))));

        // TODO: double check
        // Create a periodic table comprising of the ECDSA generator points we need to
        // add together. The columns of this table are represented by polynomials that
        // evaluate to the `i`th row when evaluated on the `i`th power of the 256th
        // root of unity. e.g.
        //
        // let:
        // - `G` be the fixed generator point of Starkware's ECDSA curve
        // - `[G]_x` denotes the x-coordinate of an elliptic-curve point P
        //
        // then our point table is:
        // ┌───────────┬──────────────────┬──────────────────┐
        // │     X     │      F_x(X)      │      F_y(X)      │
        // ├───────────┼──────────────────┼──────────────────┤
        // │    ω^0    │   [G * 2^0]_x    │   [G * 2^0]_y    │
        // ├───────────┼──────────────────┼──────────────────┤
        // │    ω^1    │   [G * 2^1]_x    │   [G * 2^1]_y    │
        // ├───────────┼──────────────────┼──────────────────┤
        // │    ...    │         ...      │         ...      │
        // ├───────────┼──────────────────┼──────────────────┤
        // │   ω^251   │  [G * 2^251]_x   │  [G * 2^251]_y   │
        // ├───────────┼──────────────────┼──────────────────┤
        // │   ω^252   │  [G * 2^251]_x   │  [G * 2^251]_y   │<- unused copy of prev
        // ├───────────┼──────────────────┼──────────────────┤
        // │   ω^253   │  [G * 2^251]_x   │  [G * 2^251]_y   │<- unused copy of prev
        // ├───────────┼──────────────────┼──────────────────┤
        // │   ω^254   │  [G * 2^251]_x   │  [G * 2^251]_y   │<- unused copy of prev
        // ├───────────┼──────────────────┼──────────────────┤
        // │   ω^255   │  [G * 2^251]_x   │  [G * 2^251]_y   │<- unused copy of prev
        // ├───────────┼──────────────────┼──────────────────┤
        // │   ω^256   │   [G * 2^0]_x    │   [G * 2^0]_y    │
        // ├───────────┼──────────────────┼──────────────────┤
        // │   ω^257   │   [G * 2^1]_x    │   [G * 2^1]_y    │
        // ├───────────┼──────────────────┼──────────────────┤
        // │    ...    │         ...      │         ...      │
        // └───────────┴──────────────────┴──────────────────┘
        let ecdsa_generator_point_x = Expr::from(Periodic(ECDSA_GENERATOR_POINT_X));
        let ecdsa_generator_point_y = Expr::from(Periodic(ECDSA_GENERATOR_POINT_Y));

        // let `P = (Px, Py)` be the point to be added (see above)
        // let `Q = (Qx, Qy)` be the partial result
        // note that the slope = dy/dx with dy = Qy - Py, dx = Qx - Px
        // this constraint is equivalent to: bit * dy = dy/dx * dx
        // NOTE: slope is 0 if bit is 0
        let ecdsa_signature0_exponentiate_generator_add_points_slope =
            (&ecdsa_sig0_exponentiate_generator_b0
                * (Ecdsa::GeneratorPartialSumY.curr() - &ecdsa_generator_point_y)
                - Ecdsa::GeneratorPartialSumSlope.curr()
                    * (Ecdsa::GeneratorPartialSumX.curr() - &ecdsa_generator_point_x))
                * &ecdsa_transition_zerofier_inv;

        // These two constraint check classic short Weierstrass curve point addition.
        // Constraint is equivalent to:
        // - `Qx_next = m^2 - Qx - Px, m = dy/dx`
        // - `Qy_next = m*(Qx - Qx_next) - Qy, m = dy/dx`
        let ecdsa_signature0_exponentiate_generator_add_points_x =
            (Ecdsa::GeneratorPartialSumSlope.curr() * Ecdsa::GeneratorPartialSumSlope.curr()
                - &ecdsa_sig0_exponentiate_generator_b0
                    * (Ecdsa::GeneratorPartialSumX.curr()
                        + &ecdsa_generator_point_x
                        + Ecdsa::GeneratorPartialSumX.next()))
                * &ecdsa_transition_zerofier_inv;
        let ecdsa_signature0_exponentiate_generator_add_points_y =
            (&ecdsa_sig0_exponentiate_generator_b0
                * (Ecdsa::GeneratorPartialSumY.curr() + Ecdsa::GeneratorPartialSumY.next())
                - Ecdsa::GeneratorPartialSumSlope.curr()
                    * (Ecdsa::GeneratorPartialSumX.curr() - Ecdsa::GeneratorPartialSumX.next()))
                * &ecdsa_transition_zerofier_inv;
        // constraint checks that the cell contains 1/(Qx - Gx)
        // Why this constraint? it checks that the Qx and Gx are not equal
        let ecdsa_signature0_exponentiate_generator_add_points_x_diff_inv =
            (Ecdsa::GeneratorPartialSumXDiffInv.curr()
                * (Ecdsa::GeneratorPartialSumX.curr() - &ecdsa_generator_point_x)
                - &one)
                * &ecdsa_transition_zerofier_inv;
        // if the bit is 0 then just copy the previous point
        let ecdsa_signature0_exponentiate_generator_copy_point_x =
            (&ecdsa_sig0_exponentiate_generator_b0_neg
                * (Ecdsa::GeneratorPartialSumX.next() - Ecdsa::GeneratorPartialSumX.curr()))
                * &ecdsa_transition_zerofier_inv;
        let ecdsa_signature0_exponentiate_generator_copy_point_y =
            (&ecdsa_sig0_exponentiate_generator_b0_neg
                * (Ecdsa::GeneratorPartialSumY.next() - Ecdsa::GeneratorPartialSumY.curr()))
                * &ecdsa_transition_zerofier_inv;

        // NOTE: exponentiate key, exponentiate generator and pedersen are almost
        // identical TODO: try DRY this code. Come up with the right
        // abstractions first though

        // Constraint operates 256 times in steps of 64 rows
        // Each row shifts the signature's `r` value to the right. E.g.
        // ```text
        // row(64 * 0 + 12):     10101...10001 <- constraint applied
        // row(64 * 1 + 12):      1010...11000 <- constraint applied
        // ...                                 <- constraint applied
        // row(64 * 255 + 12):               0 <- constraint disabled
        // row(64 * 256 + 12):   11101...10001 <- constraint applied
        // row(64 * 257 + 12):    1110...01000 <- constraint applied
        // ...                                 <- constraint applied
        // row(64 * 511 + 12):               0 <- constraint disabled
        // ...
        // ```
        let ecdsa_signature0_exponentiate_key_booleanity_test = (&ecdsa_sig0_exponentiate_key_b0
            * (&ecdsa_sig0_exponentiate_key_b0 - &one))
            * &ec_op_transition_zerofier_inv;

        let ec_op_zero_suffix_zerofier =
            X.pow(n / 16384) - Constant(FieldVariant::Fp(g.pow([(251 * n / 256) as u64])));

        // Note that with cairo's default field each element is 252 bits.
        // For Cairo's ECDSA we allow the signature's `r` value to be a 251 bit number.
        // Since we have a column that right shifts a number every 64 rows we check that
        // the suffix of row 64*251 (of every 256 row group) equals 0 e.g.
        // ```text
        // row(64 * 0 + 38):   10101...10001 <- NOTE: 1st ECDSA instance start
        // row(64 * 1 + 38):    1010...11000
        // ...
        // row(64 * 249 + 38):            10
        // row(64 * 250 + 38):             1
        // row(64 * 251 + 38):             0 <- check zero
        // row(64 * 252 + 38):             0
        // row(64 * 253 + 38):             0
        // row(64 * 254 + 38):             0
        // row(64 * 255 + 38):             0
        // row(64 * 256 + 38): 11101...10001 <- NOTE: 2nd ECDSA instance start
        // row(64 * 257 + 38):  1110...01000
        // ...
        // row(64 * 505 + 38):            11
        // row(64 * 506 + 38):             1
        // row(64 * 507 + 38):             0 <- check zero
        // row(64 * 508 + 38):             0
        // ...
        // ```
        let ecdsa_signature0_exponentiate_key_bit_extraction_end =
            Ecdsa::RSuffix.curr() / &ec_op_zero_suffix_zerofier;

        // TODO: is this constraint even needed?
        // check suffix in row 255 of each 256 row group is zero
        let ecdsa_signature0_exponentiate_key_zeros_tail = Ecdsa::RSuffix.curr()
            / (X.pow(n / 16384) - Constant(FieldVariant::Fp(g.pow([255 * n as u64 / 256]))));

        // let `P = (Px, Py)` be the doubled pubkey point to be added
        // let `Q = (Qx, Qy)` be the partial result
        // note that the slope = dy/dx with dy = Qy - Py, dx = Qx - Px
        // this constraint is equivalent to: bit * dy = dy/dx * dx
        // NOTE: slope is 0 if bit is 0
        let ecdsa_signature0_exponentiate_key_add_points_slope = (&ecdsa_sig0_exponentiate_key_b0
            * (Ecdsa::PubkeyPartialSumY.curr() - Ecdsa::PubkeyDoublingY.curr())
            - Ecdsa::PubkeyPartialSumSlope.curr()
                * (Ecdsa::PubkeyPartialSumX.curr() - Ecdsa::PubkeyDoublingX.curr()))
            * &ec_op_transition_zerofier_inv;

        // These two constraint check classic short Weierstrass curve point addition.
        // Constraint is equivalent to:
        // - `Qx_next = m^2 - Qx - Px, m = dy/dx`
        // - `Qy_next = m*(Qx - Qx_next) - Qy, m = dy/dx`
        let ecdsa_signature0_exponentiate_key_add_points_x = (Ecdsa::PubkeyPartialSumSlope.curr()
            * Ecdsa::PubkeyPartialSumSlope.curr()
            - &ecdsa_sig0_exponentiate_key_b0
                * (Ecdsa::PubkeyPartialSumX.curr()
                    + Ecdsa::PubkeyDoublingX.curr()
                    + Ecdsa::PubkeyPartialSumX.next()))
            * &ec_op_transition_zerofier_inv;
        let ecdsa_signature0_exponentiate_key_add_points_y = (&ecdsa_sig0_exponentiate_key_b0
            * (Ecdsa::PubkeyPartialSumY.curr() + Ecdsa::PubkeyPartialSumY.next())
            - Ecdsa::PubkeyPartialSumSlope.curr()
                * (Ecdsa::PubkeyPartialSumX.curr() - Ecdsa::PubkeyPartialSumX.next()))
            * &ec_op_transition_zerofier_inv;
        // constraint checks that the cell contains 1/(Qx - Px)
        // Why this constraint? it checks that the Qx and Px are not equal
        // with Px the x-coordinate of the doubled pubkey
        // and Qx the x-coordinate of the partial sum of the pubkey
        let ecdsa_signature0_exponentiate_key_add_points_x_diff_inv =
            (Ecdsa::PubkeyPartialSumXDiffInv.curr()
                * (Ecdsa::PubkeyPartialSumX.curr() - Ecdsa::PubkeyDoublingX.curr())
                - &one)
                * &ec_op_transition_zerofier_inv;
        // if the bit is 0 then just copy the previous point
        let ecdsa_signature0_exponentiate_key_copy_point_x = (&ecdsa_sig0_exponentiate_key_b0_neg
            * (Ecdsa::PubkeyPartialSumX.next() - Ecdsa::PubkeyPartialSumX.curr()))
            * &ec_op_transition_zerofier_inv;
        let ecdsa_signature0_exponentiate_key_copy_point_y = (&ecdsa_sig0_exponentiate_key_b0_neg
            * (Ecdsa::PubkeyPartialSumY.next() - Ecdsa::PubkeyPartialSumY.curr()))
            * &ec_op_transition_zerofier_inv;

        let all_ecdsa_zerofier = X.pow(n / 32768) - &one;
        let all_ecdsa_zerofier_inv = &one / all_ecdsa_zerofier;
        let all_ec_op_zerofier = X.pow(n / 16384) - &one;
        let all_ec_op_zerofier_inv = &one / all_ec_op_zerofier;

        // Check the correct starting values for our partial sums
        // ======================================================
        // #1 Check out generator `G` partial sum is offset with the `-shift_point`
        let ecdsa_sig_config_shift_point_x = Constant(FieldVariant::Fp(ecdsa::SHIFT_POINT.x));
        let ecdsa_sig_config_shift_point_y = Constant(FieldVariant::Fp(ecdsa::SHIFT_POINT.y));
        let ecdsa_signature0_init_gen_x = (Ecdsa::GeneratorPartialSumX.curr()
            - ecdsa_sig_config_shift_point_x)
            * &all_ecdsa_zerofier_inv;
        let ecdsa_signature0_init_gen_y = (Ecdsa::GeneratorPartialSumY.curr()
            + ecdsa_sig_config_shift_point_y)
            * &all_ecdsa_zerofier_inv;
        // #2 Check out pubkey partial sum is offset with the `shift_point`
        let ecdsa_signature0_init_key_x = (Ecdsa::PubkeyPartialSumX.curr()
            - ecdsa_sig_config_shift_point_x)
            * &all_ec_op_zerofier_inv;
        let ecdsa_signature0_init_key_y = (Ecdsa::PubkeyPartialSumY.curr()
            - ecdsa_sig_config_shift_point_y)
            * &all_ec_op_zerofier_inv;

        // Note that there are two elliptic curve operations that span 16384 rows each.
        // 1st is the EC operation for our pubkey partial sum
        // 2nd is the EC operation is for the partial sum of `msg_hash * G + r * P`
        // - with the signature's `r`, Curve's generator point G and pubkey P
        // This constraint checks the starting value for the 2nd EC operation
        // By checking it is the sum `msg_hash * G + r * P`
        //
        // Note: the last GeneratorPartialSum slope is repurposed for the slope of the
        // sum `(msg_hash * G) + (r * P)`.
        let ecdsa_signature0_add_results_slope = (Ecdsa::GeneratorPartialSumY.offset(255)
            - (Ecdsa::PubkeyPartialSumY.offset(255)
                + Ecdsa::BSlope.curr()
                    * (Ecdsa::GeneratorPartialSumX.offset(255)
                        - Ecdsa::PubkeyPartialSumX.offset(255))))
            * &all_ecdsa_zerofier_inv;
        // Now we have the slope finish the addition as per SW curve addition law.
        // `x = m^2 - (msg_hash * G)_x - (R * P)_x, m = dy/dx`
        // `y = m*((msg_hash*G)_x - x) - (msg_hash*G)_y, m = dy/dx`
        let ecdsa_signature0_add_results_x = (Ecdsa::BSlope.curr() * Ecdsa::BSlope.curr()
            - (Ecdsa::GeneratorPartialSumX.offset(255)
                + Ecdsa::PubkeyPartialSumX.offset(255)
                + Ecdsa::PubkeyDoublingX.offset(256)))
            * &all_ecdsa_zerofier_inv;
        // TODO: introduce more generic names for PubkeyDoublingX, PubkeyDoublingY,
        // PubkeyPartialSum* etc. since they're not just for pubkey but also the partial
        // sum of the point `(msg_hash * G) + (r * P)`.
        let ecdsa_signature0_add_results_y = (Ecdsa::GeneratorPartialSumY.offset(255)
            + Ecdsa::PubkeyDoublingY.offset(256)
            - Ecdsa::BSlope.curr()
                * (Ecdsa::GeneratorPartialSumX.offset(255) - Ecdsa::PubkeyDoublingX.offset(256)))
            * &all_ecdsa_zerofier_inv;
        // constraint checks that the cell contains 1/((msg_hash * G)_x - (r * P)_x)
        // Once again like the slope we repurpose the last GeneratorPartialSumXDiffInv
        // Why this constraint? it checks that the (msg_hash * G)_x and (r * P)_x are
        // not equal. Case (1) would mean the ys are distinct => vertical slope => sum
        // would be point at infinity - no good, case (2) would mean the points
        // are equal and there is no slope through the points
        let ecdsa_signature0_add_results_x_diff_inv = (Ecdsa::BXDiffInv.curr()
            * (Ecdsa::GeneratorPartialSumX.offset(255) - Ecdsa::PubkeyPartialSumX.offset(255))
            - &one)
            * &all_ecdsa_zerofier_inv;

        // let `B = ((msg_hash * G) + (r * P)), H = w * B`
        // Here we are trying to calculate `H - shift_point`
        // NOTE: `(H - shift_point)_x` should equal `r`
        // First we need the slope between points `H` and `-shift_point`
        let ecdsa_signature0_extract_r_slope = (Ecdsa::PubkeyPartialSumY.offset(256 + 255)
            + ecdsa_sig_config_shift_point_y
            - Ecdsa::RPointSlope.curr()
                * (Ecdsa::PubkeyPartialSumX.offset(256 + 255) - ecdsa_sig_config_shift_point_x))
            * &all_ecdsa_zerofier_inv;
        // Now we have the slope we can find the x-coordinate of `H - shift_point`
        // (which if the signature is valid will be `r`) using SW curve addition
        // law: `x = m^2 - H_x - (-shift_point)_x, m = dy/dx`
        let ecdsa_signature0_extract_r_x = (Ecdsa::RPointSlope.curr() * Ecdsa::RPointSlope.curr()
            - (Ecdsa::PubkeyPartialSumX.offset(256 + 255)
                + ecdsa_sig_config_shift_point_x
                + Ecdsa::RSuffix.curr()))
            * &all_ecdsa_zerofier_inv;
        // constraint checks that the cell contains 1/(H_x - shift_point_x)
        // Once again like the slope we repurpose the last GeneratorPartialSumXDiffInv
        let ecdsa_signature0_extract_r_x_diff_inv = (Ecdsa::RPointXDiffInv.curr()
            * (Ecdsa::PubkeyPartialSumX.offset(256 + 255) - ecdsa_sig_config_shift_point_x)
            - &one)
            * &all_ecdsa_zerofier_inv;

        // `z` refers to the message hash. Check that it's not the zero hash.
        let ecdsa_signature0_z_nonzero = (Ecdsa::MessageSuffix.curr() * Ecdsa::MessageInv.curr()
            - &one)
            * &all_ecdsa_zerofier_inv;

        // NOTE: `PubkeyDoublingSlope.offset(255)` holds a value that isn't constrained
        // Every 16370th of every 32768 rows PubkeyDoublingSlope contains r^(-1)
        // Every 32754th of every 32768 rows PubkeyDoublingSlope contains w^(-1)
        let ecdsa_signature0_r_and_w_nonzero =
            (Ecdsa::RSuffix.curr() * Ecdsa::PubkeyDoublingSlope.offset(255) - &one)
                * &all_ec_op_zerofier_inv;

        // check the pubkey `Q` is on the elliptic curve
        // aka check `y^2 = x^3 + a*x + b`
        let ecdsa_signature0_q_on_curve_x_squared = (Ecdsa::PubkeyXSquared.curr()
            - Ecdsa::PubkeyDoublingX.curr() * Ecdsa::PubkeyDoublingX.curr())
            * &all_ecdsa_zerofier_inv;
        let ecdsa_sig_config_beta = Constant(FieldVariant::Fp(ECDSA_SIG_CONFIG_BETA));
        let ecdsa_signature0_q_on_curve_on_curve = (Ecdsa::PubkeyDoublingY.curr()
            * Ecdsa::PubkeyDoublingY.curr()
            - (Ecdsa::PubkeyDoublingX.curr() * Ecdsa::PubkeyXSquared.curr()
                + Ecdsa::PubkeyDoublingX.curr() * ecdsa_sig_config_alpha
                + ecdsa_sig_config_beta))
            * &all_ecdsa_zerofier_inv;

        let last_ecdsa_zerofier =
            X - Constant(FieldVariant::Fp(g.pow([32768 * (n / 32768 - 1) as u64])));
        let all_ecdsa_except_last_zerofier_inv = &last_ecdsa_zerofier * &all_ecdsa_zerofier_inv;

        // Check starting address of the ECDSA memory segment
        // memory segments in Cairo are continuous i.e. Memory:
        // |0->100 all pedersen mem|101 -> 151 all RC mem|151 -> 900 all ECDSA mem|
        let ecdsa_init_addr =
            (Npc::EcdsaPubkeyAddr.curr() - InitialEcdsaAddr.hint()) * &first_row_zerofier_inv;

        // NOTE: message address is the 2nd address of each instance
        let ecdsa_message_addr = (Npc::EcdsaMessageAddr.curr()
            - (Npc::EcdsaPubkeyAddr.curr() + &one))
            * &all_ecdsa_zerofier_inv;

        // NOTE: pubkey address is the 1st address of each instance
        let ecdsa_pubkey_addr = (Npc::EcdsaPubkeyAddr.next()
            - (Npc::EcdsaMessageAddr.curr() + &one))
            * &all_ecdsa_except_last_zerofier_inv;

        // Check the ECDSA Message and Pubkey are correctly loaded into memory
        let ecdsa_message_value0 =
            (Npc::EcdsaMessageVal.curr() - Ecdsa::MessageSuffix.curr()) * &all_ecdsa_zerofier_inv;
        let ecdsa_pubkey_value0 =
            (Npc::EcdsaPubkeyVal.curr() - Ecdsa::PubkeyDoublingX.curr()) * &all_ecdsa_zerofier_inv;

        // bitwise builtin
        // ===============

        // check the initial bitwise segment memory address
        // all addresses associated with bitwise checks are continuous
        let bitwise_init_var_pool_addr =
            (Npc::BitwisePoolAddr.curr() - InitialBitwiseAddr.hint()) * &first_row_zerofier_inv;

        // example for trace length n=1024
        // ================================
        // x^(n/1024) - ω^(3*n/4)      = x^(n/1024) - ω^(768*n/1024)
        // x^(n/1024) - ω^(768*n/1024) = (x-ω^768)
        // x^(n/256) - 1               = (x-ω^0)(x-ω^256)(x-ω^512)(x-ω^768)
        // (x-ω^768)/(x^(n/256) - 1)   = 1/((x-ω^0)(x-ω^256)(x-ω^512))
        // vanishes on every 256th row except the 3rd of every 4
        let bitwise_transition_zerofier_inv = (X.pow(n / 1024)
            - Constant(FieldVariant::Fp(g.pow([(3 * n / 4) as u64]))))
            * &every_256_row_zerofier_inv;

        let all_bitwise_zerofier = X.pow(n / 1024) - &one;
        let all_bitwise_zerofier_inv = &one / &all_bitwise_zerofier;

        // Checks memory address for four bitwise inputs
        // `x`, `y`, `x&y` and `x^y` are continuous
        let bitwise_step_var_pool_addr = (Npc::BitwisePoolAddr.next()
            - (Npc::BitwisePoolAddr.curr() + &one))
            * &bitwise_transition_zerofier_inv;
        // need to check one more address for `x|y`
        let bitwise_x_or_y_addr = (Npc::BitwiseXOrYAddr.curr()
            - (Npc::BitwisePoolAddr.offset(3) + &one))
            * &all_bitwise_zerofier_inv;

        let last_bitwise_zerofier =
            X - Constant(FieldVariant::Fp(g.pow([1024 * (n / 1024 - 1) as u64])));
        let all_bitwise_except_last_zerofier_inv =
            &last_bitwise_zerofier * &all_bitwise_zerofier_inv;

        // check the next bitwise instance has the correct address
        let bitwise_next_var_pool_addr = (Npc::BitwisePoolAddr.offset(4)
            - (Npc::BitwiseXOrYAddr.curr() + &one))
            * &all_bitwise_except_last_zerofier_inv;

        // check all values `x`, `y`, `x&y` and `x^y` are partitioned
        // NOTE: not `x|y` since this is calculated trivially using `x&y` and `x^y`
        // Partitioning in this context is the process of breaking up our number into
        // strided bit chunks. Firstly the bottom 128 bits are handled by
        // `bitwise_sum_var_0_0` and the top 128 bits are handles by
        // `bitwise_sum_var_8_0`. Then each 128 bit chunk is broken up into two 64 bit
        // chunks. Each of these 64 bit chunks is broken up into four stridings of a
        // 16 bit integer. For example to break up the 64 bit binary integer `v`:
        // ```text
        //  v = 0b1100_1010_0110_1001_0101_0100_0100_0000_0100_0010_0001_0010_1111_0111_1100
        // s0 = 0b0000_0000_0000_0001_0001_0000_0000_0000_0000_0000_0001_0000_0001_0001_0000
        // s1 = 0b0000_0001_0001_0000_0000_0000_0000_0000_0000_0001_0000_0001_0001_0001_0000
        // s2 = 0b0001_0000_0001_0000_0001_0001_0001_0000_0001_0000_0000_0000_0001_0001_0001
        // s3 = 0b0001_0001_0000_0001_0000_0000_0000_0000_0000_0000_0000_0000_0001_0000_0001
        // ```
        // note that `v = s0 * 2^0 + s1 * 2^1 + s2 * 2^2 + s3 * 2^3`.
        let bitwise_partition = (&bitwise_sum_var_0_0 + &bitwise_sum_var_8_0
            - Npc::BitwisePoolVal.curr())
            * &every_256_row_zerofier_inv;

        // NOTE: `x | y = (x & y) + (x ^ y)`
        let bitwise_x_and_y_val = Npc::BitwisePoolVal.offset(2);
        let bitwise_x_xor_y_val = Npc::BitwisePoolVal.offset(3);
        let bitwise_or_is_and_plus_xor = (Npc::BitwiseXOrYVal.curr()
            - (bitwise_x_and_y_val + bitwise_x_xor_y_val))
            * &all_bitwise_zerofier_inv;

        // example for trace length n=2048
        // ===============================
        // x^(n/1024) - ω^(1*n/64))  = x^(n/1024) - ω^(16 * n / 1024))
        //                           = (x - ω^(16 * 1))(x - ω^(1024 + (16 * 1)))
        // x^(n/1024) - ω^(1*n/32))  = x^(n/1024) - ω^(32 * n / 1024))
        //                           = (x - ω^(16 * 2))(x - ω^(1024 + (16 * 2)))
        // x^(n/1024) - ω^(3*n/64))  = x^(n/1024) - ω^(48 * n / 1024))
        //                           = (x - ω^(16 * 3))(x - ω^(1024 + (16 * 3)))
        // x^(n/1024) - ω^(1*n/16))  = x^(n/1024) - ω^(64 * n / 1024))
        //                           = (x - ω^(16 * 4))(x - ω^(1024 + (16 * 4)))
        // x^(n/1024) - ω^(5*n/64))  = x^(n/1024) - ω^(80 * n / 1024))
        //                           = (x - ω^(16 * 5))(x - ω^(1024 + (16 * 5)))
        // x^(n/1024) - ω^(3*n/32))  = x^(n/1024) - ω^(96 * n / 1024))
        //                           = (x - ω^(16 * 6))(x - ω^(1024 + (16 * 6)))
        // x^(n/1024) - ω^(7*n/64))  = x^(n/1024) - ω^(112 * n / 1024))
        //                           = (x - ω^(16 * 7))(x - ω^(1024 + (16 * 7)))
        // x^(n/1024) - ω^(1*n/8))   = x^(n/1024) - ω^(128 * n / 1024))
        //                           = (x - ω^(16 * 8))(x - ω^(1024 + (16 * 8)))
        // x^(n/1024) - ω^(9*n/64))  = x^(n/1024) - ω^(144 * n / 1024))
        //                           = (x - ω^(16 * 9))(x - ω^(1024 + (16 * 9)))
        // x^(n/1024) - ω^(5*n/32))  = x^(n/1024) - ω^(160 * n / 1024))
        //                           = (x - ω^(16 * 10))(x - ω^(1024 + (16 * 10)))
        // x^(n/1024) - ω^(11*n/64)) = x^(n/1024) - ω^(176 * n / 1024))
        //                           = (x - ω^(16 * 11))(x - ω^(1024 + (16 * 11)))
        // x^(n/1024) - ω^(3*n/16))  = x^(n/1024) - ω^(192 * n / 1024))
        //                           = (x - ω^(16 * 12))(x - ω^(1024 + (16 * 12)))
        // x^(n/1024) - ω^(13*n/64)) = x^(n/1024) - ω^(208 * n / 1024))
        //                           = (x - ω^(16 * 13))(x - ω^(1024 + (16 * 13)))
        // x^(n/1024) - ω^(7*n/32))  = x^(n/1024) - ω^(224 * n / 1024))
        //                           = (x - ω^(16 * 14))(x - ω^(1024 + (16 * 14)))
        // x^(n/1024) - ω^(15*n/64)) = x^(n/1024) - ω^(240 * n / 1024))
        //                           = (x - ω^(16 * 15))(x - ω^(1024 + (16 * 15)))
        // NOTE: when you multiply all these together you get:
        // $\prod_{i=1}^{15}(x - ω^(16 * i))(x - ω^(1024 + (16 * i)))$
        // now multiply this product by $x^(n / 1024) - 1$
        // TODO: isn't this zerofier just equivalent to $x^(n / 16) - 1$?
        let every_16_bit_segment_zerofier = (X.pow(n / 1024)
            - Constant(FieldVariant::Fp(g.pow([n as u64 / 64]))))
            * (X.pow(n / 1024) - Constant(FieldVariant::Fp(g.pow([n as u64 / 32]))))
            * (X.pow(n / 1024) - Constant(FieldVariant::Fp(g.pow([3 * n as u64 / 64]))))
            * (X.pow(n / 1024) - Constant(FieldVariant::Fp(g.pow([n as u64 / 16]))))
            * (X.pow(n / 1024) - Constant(FieldVariant::Fp(g.pow([5 * n as u64 / 64]))))
            * (X.pow(n / 1024) - Constant(FieldVariant::Fp(g.pow([3 * n as u64 / 32]))))
            * (X.pow(n / 1024) - Constant(FieldVariant::Fp(g.pow([7 * n as u64 / 64]))))
            * (X.pow(n / 1024) - Constant(FieldVariant::Fp(g.pow([n as u64 / 8]))))
            * (X.pow(n / 1024) - Constant(FieldVariant::Fp(g.pow([9 * n as u64 / 64]))))
            * (X.pow(n / 1024) - Constant(FieldVariant::Fp(g.pow([5 * n as u64 / 32]))))
            * (X.pow(n / 1024) - Constant(FieldVariant::Fp(g.pow([11 * n as u64 / 64]))))
            * (X.pow(n / 1024) - Constant(FieldVariant::Fp(g.pow([3 * n as u64 / 16]))))
            * (X.pow(n / 1024) - Constant(FieldVariant::Fp(g.pow([13 * n as u64 / 64]))))
            * (X.pow(n / 1024) - Constant(FieldVariant::Fp(g.pow([7 * n as u64 / 32]))))
            * (X.pow(n / 1024) - Constant(FieldVariant::Fp(g.pow([15 * n as u64 / 64]))))
            * &all_bitwise_zerofier;
        let every_16_bit_segment_zerofier_inv = &one / every_16_bit_segment_zerofier;

        // NOTE: `x+y = (x^y) + (x&y) + (x&y)`
        // TODO: CHECK: only when x and y are sufficiently diluted?
        let x_16_bit_segment = Bitwise::Bits16Chunk0Offset0.offset(0);
        let y_16_bit_segment = Bitwise::Bits16Chunk0Offset0.offset(1);
        let x_and_y_16_bit_segment = Bitwise::Bits16Chunk0Offset0.offset(2);
        let x_xor_y_16_bit_segment = Bitwise::Bits16Chunk0Offset0.offset(3);
        let bitwise_addition_is_xor_with_and = (x_16_bit_segment + y_16_bit_segment
            - (x_xor_y_16_bit_segment + &x_and_y_16_bit_segment + x_and_y_16_bit_segment))
            * &every_16_bit_segment_zerofier_inv;

        // NOTE: with these constraints we force the last 4 bits of x&y and x^y to be 0
        // this is important since we are dealing with a 252bit field (not 256bit field)
        let x_and_y_16_bit_segment = Bitwise::Bits16Chunk3Offset0.offset(2);
        let x_xor_y_16_bit_segment = Bitwise::Bits16Chunk3Offset0.offset(3);
        let bitwise_unique_unpacking192 = ((x_and_y_16_bit_segment + x_xor_y_16_bit_segment)
            * (&two).pow(4)
            - Bitwise::Bits16Chunk3Offset0ResShifted.curr())
            * &all_bitwise_zerofier_inv;
        let x_and_y_16_bit_segment = Bitwise::Bits16Chunk3Offset1.offset(2);
        let x_xor_y_16_bit_segment = Bitwise::Bits16Chunk3Offset1.offset(3);
        let bitwise_unique_unpacking193 = ((x_and_y_16_bit_segment + x_xor_y_16_bit_segment)
            * (&two).pow(4)
            - Bitwise::Bits16Chunk3Offset1ResShifted.curr())
            * &all_bitwise_zerofier_inv;
        let x_and_y_16_bit_segment = Bitwise::Bits16Chunk3Offset2.offset(2);
        let x_xor_y_16_bit_segment = Bitwise::Bits16Chunk3Offset2.offset(3);
        let bitwise_unique_unpacking194 = ((x_and_y_16_bit_segment + x_xor_y_16_bit_segment)
            * (&two).pow(4)
            - Bitwise::Bits16Chunk3Offset2ResShifted.curr())
            * &all_bitwise_zerofier_inv;
        let x_and_y_16_bit_segment = Bitwise::Bits16Chunk3Offset3.offset(2);
        let x_xor_y_16_bit_segment = Bitwise::Bits16Chunk3Offset3.offset(3);
        let bitwise_unique_unpacking195 = ((x_and_y_16_bit_segment + x_xor_y_16_bit_segment)
            * (&two).pow(8)
            - Bitwise::Bits16Chunk3Offset3ResShifted.curr())
            * &all_bitwise_zerofier_inv;

        // Elliptic Curve operations builtin
        // =================================
        let ec_op_init_addr =
            (Npc::EcOpPXAddr.curr() - InitialEcOpAddr.hint()) * &first_row_zerofier_inv;

        let last_ec_op_zerofier =
            X - Constant(FieldVariant::Fp(g.pow([16384 * (n / 16384 - 1) as u64])));
        let all_ec_op_except_last_zerofier_inv = &last_ec_op_zerofier * &all_ec_op_zerofier_inv;

        // check ec op memory addresses
        let ec_op_num_memory_items = Constant(FieldVariant::Fp(Fp::from(7u8)));
        let ec_op_p_x_addr = (Npc::EcOpPXAddr.next()
            - (Npc::EcOpPXAddr.curr() + ec_op_num_memory_items))
            * &all_ec_op_except_last_zerofier_inv;
        // `p_y`'s address follows `p_x`'s address
        let ec_op_p_y_addr =
            (Npc::EcOpPYAddr.curr() - (Npc::EcOpPXAddr.curr() + &one)) * &all_ec_op_zerofier_inv;
        // `q_x`'s address follows `p_y`'s address
        let ec_op_q_x_addr =
            (Npc::EcOpQXAddr.curr() - (Npc::EcOpPYAddr.curr() + &one)) * &all_ec_op_zerofier_inv;
        // `q_y`'s address follows `q_x`'s address
        let ec_op_q_y_addr =
            (Npc::EcOpQYAddr.curr() - (Npc::EcOpQXAddr.curr() + &one)) * &all_ec_op_zerofier_inv;
        // `m`'s address follows `q_y`'s address
        let ec_op_m_addr =
            (Npc::EcOpMAddr.curr() - (Npc::EcOpQYAddr.curr() + &one)) * &all_ec_op_zerofier_inv;
        // `r_x`'s address follows `m`'s address
        let ec_op_r_x_addr =
            (Npc::EcOpRXAddr.curr() - (Npc::EcOpMAddr.curr() + &one)) * &all_ec_op_zerofier_inv;
        // `r_y`'s address follows `r_x`'s address
        let ec_op_r_y_addr =
            (Npc::EcOpRYAddr.curr() - (Npc::EcOpRXAddr.curr() + &one)) * &all_ec_op_zerofier_inv;

        // These constraint maps to the curve point doubling equation:
        // https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Point_doubling
        // ```text
        // curve eq: y^2 = x^3 + a*x + b
        // Q_i = elliptic curve point
        // Q_(i+1) = Q_i + Q_i
        // slope = (3 * Q_i.x^2 + a) / (2*Q_i.y)
        // Q_(i+1).x = slope^2 - 2*Q_i.x
        // Q_(i+1).y = slope*(Q_i.x - Q_(i+1).x) - Q_i.y
        // ```
        let ec_op_doubling_q_slope = (&ec_op_doubling_q_x_squared_0
            + &ec_op_doubling_q_x_squared_0
            + &ec_op_doubling_q_x_squared_0
            + ecdsa_sig_config_alpha
            - (EcOp::QDoublingY.curr() + EcOp::QDoublingY.curr()) * EcOp::QDoublingSlope.curr())
            * &ec_op_transition_zerofier_inv;
        let ec_op_doubling_q_x = (EcOp::QDoublingSlope.curr() * EcOp::QDoublingSlope.curr()
            - (EcOp::QDoublingX.curr() + EcOp::QDoublingX.curr() + EcOp::QDoublingX.next()))
            * &ec_op_transition_zerofier_inv;
        let ec_op_doubling_q_y = (EcOp::QDoublingY.curr() + EcOp::QDoublingY.next()
            - EcOp::QDoublingSlope.curr() * (EcOp::QDoublingX.curr() - EcOp::QDoublingX.next()))
            * &ec_op_transition_zerofier_inv;

        // check the correct `Q` point is loaded in
        let ec_op_get_q_x =
            (Npc::EcOpQXVal.curr() - EcOp::QDoublingX.curr()) * &all_ec_op_zerofier_inv;
        let ec_op_get_q_y =
            (Npc::EcOpQYVal.curr() - EcOp::QDoublingY.curr()) * &all_ec_op_zerofier_inv;

        // Use knowledge of bits 251,196,192 to determine if there is a unique unpacking
        let ec_op_ec_subset_sum_bit_unpacking_last_one_is_zero = (EcOp::MBit251AndBit196AndBit192
            .curr()
            * (EcOp::MSuffix.curr() - (EcOp::MSuffix.next() + EcOp::MSuffix.next())))
            * &all_ec_op_zerofier_inv;
        let ec_op_ec_subset_sum_bit_unpacking_zeroes_between_ones0 =
            (EcOp::MBit251AndBit196AndBit192.curr()
                * (EcOp::MSuffix.offset(1) - EcOp::MSuffix.offset(192) * shift191))
                * &all_ec_op_zerofier_inv;
        let ec_op_ec_subset_sum_bit_unpacking_cumulative_bit192 = (EcOp::MBit251AndBit196AndBit192
            .curr()
            - EcOp::MBit251AndBit196.curr()
                * (EcOp::MSuffix.offset(192)
                    - (EcOp::MSuffix.offset(193) + EcOp::MSuffix.offset(193))))
            * &all_ec_op_zerofier_inv;
        let ec_op_ec_subset_sum_bit_unpacking_zeroes_between_ones192 = (EcOp::MBit251AndBit196
            .curr()
            * (EcOp::MSuffix.offset(193) - EcOp::MSuffix.offset(196) * shift3))
            * &all_ec_op_zerofier_inv;
        let ec_op_ec_subset_sum_bit_unpacking_cumulative_bit196 = (EcOp::MBit251AndBit196.curr()
            - (EcOp::MSuffix.offset(251)
                - (EcOp::MSuffix.offset(252) + EcOp::MSuffix.offset(252)))
                * (EcOp::MSuffix.offset(196)
                    - (EcOp::MSuffix.offset(197) + EcOp::MSuffix.offset(197))))
            * &all_ec_op_zerofier_inv;
        let ec_op_ec_subset_sum_bit_unpacking_zeroes_between_ones196 =
            ((EcOp::MSuffix.offset(251) - (EcOp::MSuffix.offset(252) + EcOp::MSuffix.offset(252)))
                * (EcOp::MSuffix.offset(197) - EcOp::MSuffix.offset(251) * shift54))
                * &all_ec_op_zerofier_inv;

        // Constraint operates 256 times in steps of 64 rows
        // Each row shifts the message hash to the right. E.g.
        // ```text
        // row(64 * 0 + 18):    10101...10001 <- constraint applied
        // row(64 * 1 + 18):     1010...11000 <- constraint applied
        // ...                                <- constraint applied
        // row(64 * 255 + 18):              0 <- constraint disabled
        // row(64 * 256 + 18):  11101...10001 <- constraint applied
        // row(64 * 257 + 18):   1110...01000 <- constraint applied
        // ...                                <- constraint applied
        // row(64 * 511 + 18):              0 <- constraint disabled
        // ...
        // ```
        let ec_op_ec_subset_sum_booleanity_test = (&ec_op_ec_subset_sum_bit_0
            * (&ec_op_ec_subset_sum_bit_0 - &one))
            * &ec_op_transition_zerofier_inv;

        // Note that with Cairo's default field each element is 252 bits.
        // Therefore we are decomposing 252 bit numbers to do pedersen hash.
        // Since we have a column that right shifts a number each row we check that the
        // suffix of row 252 (of every 256 row group) equals 0 e.g.
        // ```text
        // row0:   10101...10001
        // row1:    1010...11000
        // ...               ...
        // row250:            10
        // row251:             1
        // row252:             0 <- check zero
        // row253:             0
        // row254:             0
        // row255:             0 <- check zero
        // row256: 11101...10001
        // row257:  1110...01000
        // ...               ...
        // row506:            11
        // row507:             1
        // row508:             0 <- check zero
        // row509:             0
        // ...               ...
        // ```
        let ec_op_zero_suffix_zerofier_inv =
            &one / (X.pow(n / 16384) - Constant(FieldVariant::Fp(g.pow([(63 * n / 64) as u64]))));
        let ec_op_ec_subset_sum_bit_extraction_end =
            EcOp::MSuffix.curr() * &ec_op_zero_suffix_zerofier_inv;
        let ec_op_ec_subset_sum_zeros_tail = EcOp::MSuffix.curr()
            / (X.pow(n / 16384) - Constant(FieldVariant::Fp(g.pow([255 * n as u64 / 256]))));

        // let `H = (Hx, Hy)` be the doubled point to be added
        // let `K = (Kx, Ky)` be the partial result
        // note that the slope = dy/dx with dy = Ky - Hy, dx = Kx - Hx
        // this constraint is equivalent to: bit * dy = dy/dx * dx
        // NOTE: slope is 0 if bit is 0
        let ec_op_ec_subset_sum_add_points_slope = (&ec_op_ec_subset_sum_bit_0
            * (EcOp::RPartialSumY.curr() - EcOp::QDoublingY.curr())
            - EcOp::RPartialSumSlope.curr()
                * (EcOp::RPartialSumX.curr() - EcOp::QDoublingX.curr()))
            * &ec_op_transition_zerofier_inv;

        // These two constraint check classic short Weierstrass curve point addition.
        // Constraint is equivalent to:
        // - `Kx_next = m^2 - Kx - Hx, m = dy/dx`
        // - `Ky_next = m*(Kx - Kx_next) - Ky, m = dy/dx`
        let ec_op_ec_subset_sum_add_points_x = (EcOp::RPartialSumSlope.curr()
            * EcOp::RPartialSumSlope.curr()
            - &ec_op_ec_subset_sum_bit_0
                * (EcOp::RPartialSumX.curr()
                    + EcOp::QDoublingX.curr()
                    + EcOp::RPartialSumX.next()))
            * &ec_op_transition_zerofier_inv;
        let ec_op_ec_subset_sum_add_points_y = (&ec_op_ec_subset_sum_bit_0
            * (EcOp::RPartialSumY.curr() + EcOp::RPartialSumY.next())
            - EcOp::RPartialSumSlope.curr()
                * (EcOp::RPartialSumX.curr() - EcOp::RPartialSumX.next()))
            * &ec_op_transition_zerofier_inv;
        // constraint checks that the cell contains 1/(Kx - Hx)
        // Why this constraint? it checks that the Kx and Hx are not equal
        // with Hx the x-coordinate of the doubled point Q
        // and Kx the x-coordinate of the partial sum of R
        // if this where the case we may be dividing by 0
        let ec_op_ec_subset_sum_add_points_x_diff_inv = (EcOp::RPartialSumXDiffInv.curr()
            * (EcOp::RPartialSumX.curr() - EcOp::QDoublingX.curr())
            - &one)
            * &ec_op_transition_zerofier_inv;
        // if the bit is 0 then just copy the previous point
        let ec_op_ec_subset_sum_copy_point_x = (&ec_op_ec_subset_sum_bit_0_neg
            * (EcOp::RPartialSumX.next() - EcOp::RPartialSumX.curr()))
            * &ec_op_transition_zerofier_inv;
        let ec_op_ec_subset_sum_copy_point_y = (&ec_op_ec_subset_sum_bit_0_neg
            * (EcOp::RPartialSumY.next() - EcOp::RPartialSumY.curr()))
            * &ec_op_transition_zerofier_inv;

        // check the correct scalar `m` is loaded in
        let ec_op_get_m = (EcOp::MSuffix.curr() - Npc::EcOpMVal.curr()) * &all_ec_op_zerofier_inv;
        // check the correct point `p` is loaded in
        let ec_op_get_p_x =
            (Npc::EcOpPXVal.curr() - EcOp::RPartialSumX.curr()) * &all_ec_op_zerofier_inv;
        let ec_op_get_p_y =
            (Npc::EcOpPYVal.curr() - EcOp::RPartialSumY.curr()) * &all_ec_op_zerofier_inv;
        // check the point `r` is set correctly in memory
        let ec_op_set_r_x =
            (Npc::EcOpRXVal.curr() - EcOp::RPartialSumX.offset(255)) * &all_ec_op_zerofier_inv;
        let ec_op_set_r_y =
            (Npc::EcOpRYVal.curr() - EcOp::RPartialSumY.offset(255)) * &all_ec_op_zerofier_inv;

        // Poseidon operations builtin
        // ===========================
        // Check the initial memory address of the poseidon segment
        let poseidon_init_input_output_addr =
            (Npc::PoseidonInput0Addr.curr() - InitialPoseidonAddr.hint()) * &first_row_zerofier_inv;

        // examples for trace length n=512
        // ===============================
        // x^(n/512)-g^(5*n/8)     = x^(n/512)-g^(320*n/512)
        // x^(n/512)-g^(320*n/512) = (x-ω^320)
        //
        // x^(n/512)-g^(3*n/4)     = x^(n/512)-g^(384*n/512)
        // x^(n/512)-g^(384*n/512) = (x-ω^384)
        // x^(n/512)-g^(7*n/8)     = x^(n/512)-g^(448*n/512)
        // x^(n/512)-g^(448*n/512) = (x-ω^448)
        // domain14                = (x^(n/512)-g^(3*n/4))*(x^(n/512)-g^(7*n/8))
        //
        // (x-ω^320)(x-ω^384)(x-ω^448)               = (x-ω^(64*5))..(x-ω^(64*7))
        // x^(n/64)-1                                = (x-ω^(64*0))..(x-ω^(64*7))
        // (x-ω^320)(x-ω^384)(x-ω^448)/(x^(n/64)-1)  = (x-ω^(64*0))..(x-ω^(64*4))
        // poseidon_inputs_outputs_step_zerofier_inv = 1/(x-ω^(64*0))..(x-ω^(64*4))
        let domain14 = (X.pow(n / 512) - Constant(FieldVariant::Fp(g.pow([3 * n as u64 / 4]))))
            * (X.pow(n / 512) - Constant(FieldVariant::Fp(g.pow([7 * n as u64 / 8]))));
        let domain15 =
            (X.pow(n / 512) - Constant(FieldVariant::Fp(g.pow([5 * n as u64 / 8])))) * &domain14;
        let poseidon_inputs_outputs_step_zerofier_inv = &domain15 * &every_64_row_zerofier_inv;
        // TODO: this constraint while accurate isn't expressed well here
        // note that the constraint checks the memory addresses are continuous for the 6
        // memory locations used per poseidon hash instance
        let poseidon_addr_input_output_step_inner = (Npc::PoseidonInput1Addr.curr()
            - (Npc::PoseidonInput0Addr.curr() + &one))
            * &poseidon_inputs_outputs_step_zerofier_inv;

        let all_poseidon_zerofier = X.pow(n / 512) - &one;
        let all_poseidon_zerofier_inv = &one / all_poseidon_zerofier;
        let all_poseidon_zerofier_except_last_inv =
            (X - Constant(FieldVariant::Fp(g.pow([512 * (n as u64 / 512 - 1)]))))
                * &all_poseidon_zerofier_inv;

        // Check the memory addresses for the next poseidon instance are directly after
        // the last address of the previous instance
        let poseidon_addr_input_output_step_outter = (Npc::PoseidonInput0Addr.next()
            - (Npc::PoseidonOutput2Addr.curr() + &one))
            * &all_poseidon_zerofier_except_last_inv;

        // examples for trace length n=512
        // ===============================
        // domain14 = (x^(n/512)-g^(3*n/4)) * (x^(n/512)-g^(7*n/8))
        //          = (x-ω^(16*24))(x-ω^(16*28))
        //
        // domain16 = x^(n/512) - g^(31*n/32)
        //          = (x-ω^(16*31))
        //
        // domain17 = (x^(n/512)-g^(11*n/16)) * (x^(n/512)-g^(23*n/32))
        //             * (x^(n/512)-g^(25*n/32)) * (x^(n/512)-g^(13*n/16))
        //             * (x^(n/512)-g^(27*n/32)) * (x^(n/512)-g^(29*n/32))
        //             * (x^(n/512)-g^(15*n/16)) * domain16
        //          = (x-ω^(16*22))(x-ω^(16*23))(x-ω^(16*25))(x-ω^(16*26))
        //             * (x-ω^(16*27))(x-ω^(16*29))(x-ω^(16*30))(x-ω^(16*31))
        //
        // domain14*domain17                = (x-ω^(16*22))..(x-ω^(16*31))
        // domain14*domain17 / (x^(n/16)-1) = 1/((x-ω^(16*0))..(x-ω^(16*21)))
        let domain16 = X.pow(n / 512) - Constant(FieldVariant::Fp(g.pow([31 * n as u64 / 32])));
        let domain17 = (X.pow(n / 512) - Constant(FieldVariant::Fp(g.pow([11 * n as u64 / 16]))))
            * (X.pow(n / 512) - Constant(FieldVariant::Fp(g.pow([23 * n as u64 / 32]))))
            * (X.pow(n / 512) - Constant(FieldVariant::Fp(g.pow([25 * n as u64 / 32]))))
            * (X.pow(n / 512) - Constant(FieldVariant::Fp(g.pow([13 * n as u64 / 16]))))
            * (X.pow(n / 512) - Constant(FieldVariant::Fp(g.pow([27 * n as u64 / 32]))))
            * (X.pow(n / 512) - Constant(FieldVariant::Fp(g.pow([29 * n as u64 / 32]))))
            * (X.pow(n / 512) - Constant(FieldVariant::Fp(g.pow([15 * n as u64 / 16]))))
            * &domain16;

        // Our AIR blowup factor is 2 but we need to check a cube
        // We use another field to spread the calculation of the cube across 2 trace
        // cells so the constraints remain with a blowup factor of 2.
        let poseidon_poseidon_full_rounds_state0_squaring = (Poseidon::FullRoundsState0.curr()
            * Poseidon::FullRoundsState0.curr()
            - Poseidon::FullRoundsState0Squared.curr())
            * &every_64_row_zerofier_inv;
        let poseidon_poseidon_full_rounds_state1_squaring = (Poseidon::FullRoundsState1.curr()
            * Poseidon::FullRoundsState1.curr()
            - Poseidon::FullRoundsState1Squared.curr())
            * &every_64_row_zerofier_inv;
        let poseidon_poseidon_full_rounds_state2_squaring = (Poseidon::FullRoundsState2.curr()
            * Poseidon::FullRoundsState2.curr()
            - Poseidon::FullRoundsState2Squared.curr())
            * &every_64_row_zerofier_inv;
        let poseidon_poseidon_partial_rounds_state0_squaring =
            (Poseidon::PartialRoundsState0.curr() * Poseidon::PartialRoundsState0.curr()
                - Poseidon::PartialRoundsState0Squared.curr())
                * &every_8_row_zerofier_inv;
        // zerofier forces this constraint every cycle but only in the
        // 1st, 2nd, ..., 22nd of every group of 32 cycles.
        let poseidon_poseidon_partial_rounds_state1_squaring =
            (Poseidon::PartialRoundsState1.curr() * Poseidon::PartialRoundsState1.curr()
                - Poseidon::PartialRoundsState1Squared.curr())
                * &domain14
                * &domain17
                * &all_cycles_zerofier_inv;

        // check the loading of the inputs into the initial state
        let poseidon_poseidon_add_first_round_key0 = (Npc::PoseidonInput0Val.curr()
            + Constant(FieldVariant::Fp(poseidon::params::ROUND_KEYS[0][0]))
            - Poseidon::FullRoundsState0.curr())
            * &all_poseidon_zerofier_inv;
        let poseidon_poseidon_add_first_round_key1 = (Npc::PoseidonInput1Val.curr()
            + Constant(FieldVariant::Fp(poseidon::params::ROUND_KEYS[0][1]))
            - Poseidon::FullRoundsState1.curr())
            * &all_poseidon_zerofier_inv;
        let poseidon_poseidon_add_first_round_key2 = (Npc::PoseidonInput2Val.curr()
            + Constant(FieldVariant::Fp(poseidon::params::ROUND_KEYS[0][2]))
            - Poseidon::FullRoundsState2.curr())
            * &all_poseidon_zerofier_inv;

        // Construct the 5 periodic columns used for Poseidon hash
        // The periodic columns encode round keys used for full and partial rounds
        let poseidon_poseidon_full_round_key0 =
            Expr::from(Periodic(POSEIDON_POSEIDON_FULL_ROUND_KEY0));
        let poseidon_poseidon_full_round_key1 =
            Expr::from(Periodic(POSEIDON_POSEIDON_FULL_ROUND_KEY1));
        let poseidon_poseidon_full_round_key2 =
            Expr::from(Periodic(POSEIDON_POSEIDON_FULL_ROUND_KEY2));
        let poseidon_poseidon_partial_round_key0 =
            Expr::from(Periodic(POSEIDON_POSEIDON_PARTIAL_ROUND_KEY0));
        let poseidon_poseidon_partial_round_key1 =
            Expr::from(Periodic(POSEIDON_POSEIDON_PARTIAL_ROUND_KEY1));

        // examples for trace length n=512
        // ===============================
        // x^(n/256) - g^(3*n/4)     = x^(n/256) - g^(192*n/256)
        // x^(n/256) - g^(192*n/256) = (x-ω^(64*3))(x-ω^(256+64*3))
        // zerofier applies every every 64 rows except the 192nd of every 256
        // NOTE: there are 8 poseidon full founds. The first half are done before the
        // partial rounds. the second half are done after the partial rounds.
        // This zerofier constraints the transition of each full round half.
        let poseidon_half_full_round_transition_zerofier_inv = (X.pow(n / 256)
            - Constant(FieldVariant::Fp(g.pow([3 * n as u64 / 4]))))
            * &every_64_row_zerofier_inv;

        // These constraints check the next full round state gets multiplied by the MDS
        // matrix and has the appropriate round key's added to them
        let poseidon_poseidon_full_round0 = (Poseidon::FullRoundsState0.next()
            - (&poseidon_poseidon_full_rounds_state0_cubed_0
                + &poseidon_poseidon_full_rounds_state0_cubed_0
                + &poseidon_poseidon_full_rounds_state0_cubed_0
                + &poseidon_poseidon_full_rounds_state1_cubed_0
                + &poseidon_poseidon_full_rounds_state2_cubed_0
                + &poseidon_poseidon_full_round_key0))
            * &poseidon_half_full_round_transition_zerofier_inv;
        let poseidon_poseidon_full_round1 = (Poseidon::FullRoundsState1.next()
            + &poseidon_poseidon_full_rounds_state1_cubed_0
            - (&poseidon_poseidon_full_rounds_state0_cubed_0
                + &poseidon_poseidon_full_rounds_state2_cubed_0
                + &poseidon_poseidon_full_round_key1))
            * &poseidon_half_full_round_transition_zerofier_inv;
        let poseidon_poseidon_full_round2 = (Poseidon::FullRoundsState2.next()
            + &poseidon_poseidon_full_rounds_state2_cubed_0
            + &poseidon_poseidon_full_rounds_state2_cubed_0
            - (&poseidon_poseidon_full_rounds_state0_cubed_0
                + &poseidon_poseidon_full_rounds_state1_cubed_0
                + &poseidon_poseidon_full_round_key2))
            * &poseidon_half_full_round_transition_zerofier_inv;

        // check the outputs are loaded into the correct memory slots
        // NOTE: also checks the final multiplication by the MDS matrix
        let poseidon_poseidon_last_full_round0 = (Npc::PoseidonOutput0Val.curr()
            - (&poseidon_poseidon_full_rounds_state0_cubed_7
                + &poseidon_poseidon_full_rounds_state0_cubed_7
                + &poseidon_poseidon_full_rounds_state0_cubed_7
                + &poseidon_poseidon_full_rounds_state1_cubed_7
                + &poseidon_poseidon_full_rounds_state2_cubed_7))
            * &all_poseidon_zerofier_inv;
        let poseidon_poseidon_last_full_round1 = (Npc::PoseidonOutput1Val.curr()
            + &poseidon_poseidon_full_rounds_state1_cubed_7
            - (&poseidon_poseidon_full_rounds_state0_cubed_7
                + &poseidon_poseidon_full_rounds_state2_cubed_7))
            * &all_poseidon_zerofier_inv;
        let poseidon_poseidon_last_full_round2 = (Npc::PoseidonOutput2Val.curr()
            + &poseidon_poseidon_full_rounds_state2_cubed_7
            + &poseidon_poseidon_full_rounds_state2_cubed_7
            - (&poseidon_poseidon_full_rounds_state0_cubed_7
                + &poseidon_poseidon_full_rounds_state1_cubed_7))
            * &all_poseidon_zerofier_inv;

        // NOTE: there are 83 partial rounds split across two different columns. The
        // first column is capable of 64 rounds the second column is capable of 32
        // rounds. Note that the constraints on the second column are such that it's
        // only capable of 22 rounds. That leaves `64 + 22 = 86` rounds which is still
        // too many. This constraint checks that the second column starts from the 61st
        // rounds from the first column - basically making the last 3 in the first
        // column redundant. This is how we get the constraint to apply to the
        // `61 + 22 = 83` unique partial rounds.
        let poseidon_poseidon_copy_partial_rounds0_i0 = (Poseidon::PartialRoundsState0.offset(61)
            - Poseidon::PartialRoundsState1.offset(0))
            * &all_poseidon_zerofier_inv;
        let poseidon_poseidon_copy_partial_rounds0_i1 = (Poseidon::PartialRoundsState0.offset(62)
            - Poseidon::PartialRoundsState1.offset(1))
            * &all_poseidon_zerofier_inv;
        let poseidon_poseidon_copy_partial_rounds0_i2 = (Poseidon::PartialRoundsState0.offset(63)
            - Poseidon::PartialRoundsState1.offset(2))
            * &all_poseidon_zerofier_inv;

        // Check the last state of full rounds (first half) is copied into the first
        // state of partial rounds. NOTE: also checks the last full round (first half
        // only) multiplication by the MDS matrix and addition of appropriate round keys
        let margin_full_to_partial_round_keys = poseidon::params::PARTIAL_ROUND_KEYS[0];
        let poseidon_poseidon_margin_full_to_partial0 = (Poseidon::PartialRoundsState0.offset(0)
            + &poseidon_poseidon_full_rounds_state2_cubed_3
            + &poseidon_poseidon_full_rounds_state2_cubed_3
            - (&poseidon_poseidon_full_rounds_state0_cubed_3
                + &poseidon_poseidon_full_rounds_state1_cubed_3
                + Constant(FieldVariant::Fp(margin_full_to_partial_round_keys[2]))))
            * &all_poseidon_zerofier_inv;
        let margin_full_to_partial1_round_key =
            MontFp!("2006642341318481906727563724340978325665491359415674592697055778067937914672");
        let poseidon_poseidon_margin_full_to_partial1 = (Poseidon::PartialRoundsState0.offset(1)
            - (&poseidon_poseidon_full_rounds_state1_cubed_3
                * Constant(FieldVariant::Fp(-Fp::from(4u8)))
                + &poseidon_poseidon_full_rounds_state2_cubed_3
                    * Constant(FieldVariant::Fp(Fp::from(10u8)))
                + Poseidon::PartialRoundsState0.offset(0)
                    * Constant(FieldVariant::Fp(Fp::from(4u8)))
                + &poseidon_poseidon_partial_rounds_state0_cubed_0
                    * Constant(FieldVariant::Fp(-Fp::from(2)))
                + Constant(FieldVariant::Fp(margin_full_to_partial1_round_key))))
            * &all_poseidon_zerofier_inv;
        let margin_full_to_partial2_round_key =
            MontFp!("427751140904099001132521606468025610873158555767197326325930641757709538586");
        let poseidon_poseidon_margin_full_to_partial2 = (Poseidon::PartialRoundsState0.offset(2)
            - (&poseidon_poseidon_full_rounds_state2_cubed_3
                * Constant(FieldVariant::Fp(Fp::from(8u8)))
                + Poseidon::PartialRoundsState0.offset(0)
                    * Constant(FieldVariant::Fp(Fp::from(4u8)))
                + &poseidon_poseidon_partial_rounds_state0_cubed_0
                    * Constant(FieldVariant::Fp(Fp::from(6u8)))
                + Poseidon::PartialRoundsState0.offset(1)
                + Poseidon::PartialRoundsState0.offset(1)
                + &poseidon_poseidon_partial_rounds_state0_cubed_1
                    * Constant(FieldVariant::Fp(-Fp::from(2)))
                + Constant(FieldVariant::Fp(margin_full_to_partial2_round_key))))
            * &all_poseidon_zerofier_inv;

        // examples for trace length n=512
        // ===============================
        // domain16 = x^(n/512) - g^(31*n/32)
        //          = (x-ω^(8*64))
        //
        // domain19 = (x^(n/512) - g^(61*n/64))
        //             * (x^(n/512) - g^(63*n/64))
        //             * domain16
        //          = (x-ω^(8*61))(x-ω^(8*62))(x-ω^(8*63))
        let domain19 = (X.pow(n / 512) - Constant(FieldVariant::Fp(g.pow([61 * n as u64 / 64]))))
            * (X.pow(n / 512) - Constant(FieldVariant::Fp(g.pow([63 * n as u64 / 64]))))
            * &domain16;
        // Check the first `64 - 3` partial rounds. NOTE: We've already checked the
        // first 3 partial rounds so they are skipped.
        let poseidon_poseidon_partial_round0 = (Poseidon::PartialRoundsState0.offset(3)
            - (&poseidon_poseidon_partial_rounds_state0_cubed_0
                * Constant(FieldVariant::Fp(Fp::from(8u8)))
                + Poseidon::PartialRoundsState0.offset(1)
                    * Constant(FieldVariant::Fp(Fp::from(4u8)))
                + &poseidon_poseidon_partial_rounds_state0_cubed_1
                    * Constant(FieldVariant::Fp(Fp::from(6u8)))
                + Poseidon::PartialRoundsState0.offset(2)
                + Poseidon::PartialRoundsState0.offset(2)
                + &poseidon_poseidon_partial_rounds_state0_cubed_2
                    * Constant(FieldVariant::Fp(-Fp::from(2u8)))
                + &poseidon_poseidon_partial_round_key0))
            * &domain19
            * &every_8_row_zerofier_inv;

        // examples for trace length n=512
        // ===============================
        // domain14 = (x-ω^(16*24))(x-ω^(16*28))
        // domain15 = (x-ω^(16*20)) * domain14
        // domain16 = (x-ω^(16*31))
        // domain17 = (x-ω^(16*22))(x-ω^(16*23))(x-ω^(16*25))(x-ω^(16*26))
        //             * (x-ω^(16*27))(x-ω^(16*29))(x-ω^(16*30)) * domain16
        //
        // domain20 = (x^(n/512)-g^(19*n/32)) * (x^(n/512)-g^(21*n/32))
        //             * domain15 * domain17
        //          = (x-ω^(16*19))(x-ω^(16*21)) * domain15 * domain17
        //          = (x-ω^(16*19))..(x-ω^(16*31))
        let domain20 = (X.pow(n / 512) - Constant(FieldVariant::Fp(g.pow([19 * n as u64 / 32]))))
            * (X.pow(n / 512) - Constant(FieldVariant::Fp(g.pow([21 * n as u64 / 32]))))
            * &domain15
            * &domain17;
        // constraint matches same structure as `poseidon_poseidon_partial_round0`
        // but zerofier is slightly different. NOTE: there are 83 partial rounds. In the
        // first column we checked 64/83 of those rounds. The last 3 rounds from the
        // first column are copied into the first rounds of this column (which
        // are skipped) and then this constraint applies to the remaining 19
        // rounds.
        let poseidon_poseidon_partial_round1 = (Poseidon::PartialRoundsState1.offset(3)
            - (&poseidon_poseidon_partial_rounds_state1_cubed_0
                * Constant(FieldVariant::Fp(Fp::from(8u8)))
                + Poseidon::PartialRoundsState1.offset(1)
                    * Constant(FieldVariant::Fp(Fp::from(4u8)))
                + poseidon_poseidon_partial_rounds_state1_cubed_1
                    * Constant(FieldVariant::Fp(Fp::from(6u8)))
                + Poseidon::PartialRoundsState1.offset(2)
                + Poseidon::PartialRoundsState1.offset(2)
                + &poseidon_poseidon_partial_rounds_state1_cubed_2
                    * Constant(FieldVariant::Fp(-Fp::from(2u8)))
                + &poseidon_poseidon_partial_round_key1))
            * &domain20
            * &all_cycles_zerofier_inv;

        // Check the last state of the partial rounds is copied into the first
        // state of full rounds (2nd half i.e. last half) rounds. NOTE: also checks the
        // last partial round multiplication by the MDS matrix and addition of
        // appropriate round keys
        let margin_partial_to_full0_round_key =
            MontFp!("560279373700919169769089400651532183647886248799764942664266404650165812023");
        let poseidon_poseidon_margin_partial_to_full0 = (Poseidon::FullRoundsState0.offset(4)
            - (&poseidon_poseidon_partial_rounds_state1_cubed_19
                * Constant(FieldVariant::Fp(Fp::from(16u8)))
                + Poseidon::PartialRoundsState1.offset(20)
                    * Constant(FieldVariant::Fp(Fp::from(8u8)))
                + &poseidon_poseidon_partial_rounds_state1_cubed_20
                    * Constant(FieldVariant::Fp(Fp::from(16u8)))
                + Poseidon::PartialRoundsState1.offset(21)
                    * Constant(FieldVariant::Fp(Fp::from(6u8)))
                + &poseidon_poseidon_partial_rounds_state1_cubed_21
                + Constant(FieldVariant::Fp(margin_partial_to_full0_round_key))))
            * &all_poseidon_zerofier_inv;
        let margin_partial_to_full1_round_key =
            MontFp!("1401754474293352309994371631695783042590401941592571735921592823982231996415");
        let poseidon_poseidon_margin_partial_to_full1 = (Poseidon::FullRoundsState1.offset(4)
            - (&poseidon_poseidon_partial_rounds_state1_cubed_20
                * Constant(FieldVariant::Fp(Fp::from(4u8)))
                + Poseidon::PartialRoundsState1.offset(21)
                + Poseidon::PartialRoundsState1.offset(21)
                + &poseidon_poseidon_partial_rounds_state1_cubed_21
                + Constant(FieldVariant::Fp(margin_partial_to_full1_round_key))))
            * &all_poseidon_zerofier_inv;
        let margin_partial_to_full2_round_key =
            MontFp!("1246177936547655338400308396717835700699368047388302793172818304164989556526");
        let poseidon_poseidon_margin_partial_to_full2 = (Poseidon::FullRoundsState2.offset(4)
            - (&poseidon_poseidon_partial_rounds_state1_cubed_19
                * Constant(FieldVariant::Fp(Fp::from(8u8)))
                + Poseidon::PartialRoundsState1.offset(20)
                    * Constant(FieldVariant::Fp(Fp::from(4u8)))
                + &poseidon_poseidon_partial_rounds_state1_cubed_20
                    * Constant(FieldVariant::Fp(Fp::from(6u8)))
                + Poseidon::PartialRoundsState1.offset(21)
                + Poseidon::PartialRoundsState1.offset(21)
                + &poseidon_poseidon_partial_rounds_state1_cubed_21
                    * Constant(FieldVariant::Fp(-Fp::from(2u8)))
                + Constant(FieldVariant::Fp(margin_partial_to_full2_round_key))))
            * &all_poseidon_zerofier_inv;

        // NOTE: for composition OODs only seem to involve one random per constraint
        vec![
            cpu_decode_opcode_rc_b,
            cpu_decode_opcode_rc_zero,
            cpu_decode_opcode_rc_input,
            cpu_decode_flag_op1_base_op0_bit,
            cpu_decode_flag_res_op1_bit,
            cpu_decode_flag_pc_update_regular_bit,
            cpu_decode_fp_update_regular_bit,
            cpu_operands_mem_dst_addr,
            cpu_operands_mem_op0_addr,
            cpu_operands_mem_op1_addr,
            cpu_operands_ops_mul,
            cpu_operands_res,
            cpu_update_registers_update_pc_tmp0,
            cpu_update_registers_update_pc_tmp1,
            cpu_update_registers_update_pc_pc_cond_negative,
            cpu_update_registers_update_pc_pc_cond_positive,
            cpu_update_registers_update_ap_ap_update,
            cpu_update_registers_update_fp_fp_update,
            cpu_opcodes_call_push_fp,
            cpu_opcodes_call_push_pc,
            cpu_opcodes_call_off0,
            cpu_opcodes_call_off1,
            cpu_opcodes_call_flags,
            cpu_opcodes_ret_off0,
            cpu_opcodes_ret_off2,
            cpu_opcodes_ret_flags,
            cpu_opcodes_assert_eq_assert_eq,
            initial_ap,
            initial_fp,
            initial_pc,
            final_ap,
            final_fp,
            final_pc,
            memory_multi_column_perm_perm_init0,
            memory_multi_column_perm_perm_step0,
            memory_multi_column_perm_perm_last,
            memory_diff_is_bit,
            memory_is_func,
            memory_initial_addr,
            public_memory_addr_zero,
            public_memory_value_zero,
            rc16_perm_init0,
            rc16_perm_step0,
            rc16_perm_last,
            rc16_diff_is_bit,
            rc16_minimum,
            rc16_maximum,
            diluted_check_permutation_init0,
            diluted_check_permutation_step0,
            diluted_check_permutation_last,
            diluted_check_init,
            diluted_check_first_element,
            diluted_check_step,
            diluted_check_last,
            pedersen_hash0_ec_subset_sub_bit_unpacking_last_one_is_zero,
            pedersen_hash0_ec_subset_sub_bit_unpacking_zeros_between_ones,
            pedersen_hash0_ec_subset_sum_bit_unpacking_cumulative_bit192,
            pedersen_hash0_ec_subset_sum_bit_unpacking_zeroes_between_ones192,
            pedersen_hash0_ec_subset_sum_bit_unpacking_cumulative_bit196,
            pedersen_hash0_ec_subset_sum_bit_unpacking_zeroes_between_ones196,
            pedersen_hash0_ec_subset_sum_booleanity_test,
            pedersen_hash0_ec_subset_sum_bit_extraction_end,
            pedersen_hash0_ec_subset_sum_zeros_tail,
            pedersen_hash0_ec_subset_sum_add_points_slope,
            pedersen_hash0_ec_subset_sum_add_points_x,
            pedersen_hash0_ec_subset_sum_add_points_y,
            pedersen_hash0_ec_subset_sum_copy_point_x,
            pedersen_hash0_ec_subset_sum_copy_point_y,
            pedersen_hash0_copy_point_x,
            pedersen_hash0_copy_point_y,
            pedersen_hash0_init_x,
            pedersen_hash0_init_y,
            pedersen_input0_value0,
            pedersen_input0_addr,
            pedersen_init_addr,
            pedersen_input1_value0,
            pedersen_input1_addr,
            pedersen_output_value0,
            pedersen_output_addr,
            rc_builtin_value,
            rc_builtin_addr_step,
            rc_builtin_init_addr,
            ecdsa_signature0_doubling_key_slope,
            ecdsa_signature0_doubling_key_x,
            ecdsa_signature0_doubling_key_y,
            ecdsa_signature0_exponentiate_generator_booleanity_test,
            ecdsa_signature0_exponentiate_generator_bit_extraction_end,
            ecdsa_signature0_exponentiate_generator_zeros_tail,
            ecdsa_signature0_exponentiate_generator_add_points_slope,
            ecdsa_signature0_exponentiate_generator_add_points_x,
            ecdsa_signature0_exponentiate_generator_add_points_y,
            ecdsa_signature0_exponentiate_generator_add_points_x_diff_inv,
            ecdsa_signature0_exponentiate_generator_copy_point_x,
            ecdsa_signature0_exponentiate_generator_copy_point_y,
            ecdsa_signature0_exponentiate_key_booleanity_test,
            ecdsa_signature0_exponentiate_key_bit_extraction_end,
            ecdsa_signature0_exponentiate_key_zeros_tail,
            ecdsa_signature0_exponentiate_key_add_points_slope,
            ecdsa_signature0_exponentiate_key_add_points_x,
            ecdsa_signature0_exponentiate_key_add_points_y,
            ecdsa_signature0_exponentiate_key_add_points_x_diff_inv,
            ecdsa_signature0_exponentiate_key_copy_point_x,
            ecdsa_signature0_exponentiate_key_copy_point_y,
            ecdsa_signature0_init_gen_x,
            ecdsa_signature0_init_gen_y,
            ecdsa_signature0_init_key_x,
            ecdsa_signature0_init_key_y,
            ecdsa_signature0_add_results_slope,
            ecdsa_signature0_add_results_x,
            ecdsa_signature0_add_results_y,
            ecdsa_signature0_add_results_x_diff_inv,
            ecdsa_signature0_extract_r_slope,
            ecdsa_signature0_extract_r_x,
            ecdsa_signature0_extract_r_x_diff_inv,
            ecdsa_signature0_z_nonzero,
            ecdsa_signature0_r_and_w_nonzero,
            ecdsa_signature0_q_on_curve_x_squared,
            ecdsa_signature0_q_on_curve_on_curve,
            ecdsa_init_addr,
            ecdsa_message_addr,
            ecdsa_pubkey_addr,
            ecdsa_message_value0,
            ecdsa_pubkey_value0,
            bitwise_init_var_pool_addr,
            bitwise_step_var_pool_addr,
            bitwise_x_or_y_addr,
            bitwise_next_var_pool_addr,
            bitwise_partition,
            bitwise_or_is_and_plus_xor,
            bitwise_addition_is_xor_with_and,
            bitwise_unique_unpacking192,
            bitwise_unique_unpacking193,
            bitwise_unique_unpacking194,
            bitwise_unique_unpacking195,
            ec_op_init_addr,
            ec_op_p_x_addr,
            ec_op_p_y_addr,
            ec_op_q_x_addr,
            ec_op_q_y_addr,
            ec_op_m_addr,
            ec_op_r_x_addr,
            ec_op_r_y_addr,
            ec_op_doubling_q_slope,
            ec_op_doubling_q_x,
            ec_op_doubling_q_y,
            ec_op_get_q_x,
            ec_op_get_q_y,
            ec_op_ec_subset_sum_bit_unpacking_last_one_is_zero,
            ec_op_ec_subset_sum_bit_unpacking_zeroes_between_ones0,
            ec_op_ec_subset_sum_bit_unpacking_cumulative_bit192,
            ec_op_ec_subset_sum_bit_unpacking_zeroes_between_ones192,
            ec_op_ec_subset_sum_bit_unpacking_cumulative_bit196,
            ec_op_ec_subset_sum_bit_unpacking_zeroes_between_ones196,
            ec_op_ec_subset_sum_booleanity_test,
            ec_op_ec_subset_sum_bit_extraction_end,
            ec_op_ec_subset_sum_zeros_tail,
            ec_op_ec_subset_sum_add_points_slope,
            ec_op_ec_subset_sum_add_points_x,
            ec_op_ec_subset_sum_add_points_y,
            ec_op_ec_subset_sum_add_points_x_diff_inv,
            ec_op_ec_subset_sum_copy_point_x,
            ec_op_ec_subset_sum_copy_point_y,
            ec_op_get_m,
            ec_op_get_p_x,
            ec_op_get_p_y,
            ec_op_set_r_x,
            ec_op_set_r_y,
            poseidon_init_input_output_addr,
            poseidon_addr_input_output_step_inner,
            poseidon_addr_input_output_step_outter,
            poseidon_poseidon_full_rounds_state0_squaring,
            poseidon_poseidon_full_rounds_state1_squaring,
            poseidon_poseidon_full_rounds_state2_squaring,
            poseidon_poseidon_partial_rounds_state0_squaring,
            poseidon_poseidon_partial_rounds_state1_squaring,
            poseidon_poseidon_add_first_round_key0,
            poseidon_poseidon_add_first_round_key1,
            poseidon_poseidon_add_first_round_key2,
            poseidon_poseidon_full_round0,
            poseidon_poseidon_full_round1,
            poseidon_poseidon_full_round2,
            poseidon_poseidon_last_full_round0,
            poseidon_poseidon_last_full_round1,
            poseidon_poseidon_last_full_round2,
            poseidon_poseidon_copy_partial_rounds0_i0,
            poseidon_poseidon_copy_partial_rounds0_i1,
            poseidon_poseidon_copy_partial_rounds0_i2,
            poseidon_poseidon_margin_full_to_partial0,
            poseidon_poseidon_margin_full_to_partial1,
            poseidon_poseidon_margin_full_to_partial2,
            poseidon_poseidon_partial_round0,
            poseidon_poseidon_partial_round1,
            poseidon_poseidon_margin_partial_to_full0,
            poseidon_poseidon_margin_partial_to_full1,
            poseidon_poseidon_margin_partial_to_full2,
        ]
        .into_iter()
        .map(Constraint::new)
        .collect()
    }

    fn composition_constraint(
        _trace_len: usize,
        constraints: &[Constraint<FieldVariant<Self::Fp, Self::Fq>>],
    ) -> CompositionConstraint<FieldVariant<Self::Fp, Self::Fq>> {
        use CompositionItem::*;
        let alpha = Expr::Leaf(CompositionCoeff(0));
        let expr = constraints
            .iter()
            .enumerate()
            .map(|(i, constraint)| {
                let constraint = constraint.map_leaves(&mut |&leaf| Item(leaf));
                constraint * (&alpha).pow(i)
            })
            .sum::<Expr<CompositionItem<FieldVariant<Self::Fp, Self::Fq>>>>()
            .reuse_shared_nodes();
        CompositionConstraint::new(expr)
    }

    fn gen_hints(
        trace_len: usize,
        execution_info: &AirPublicInput<Self::Fp>,
        challenges: &Challenges<Self::Fq>,
    ) -> Hints<Self::Fq> {
        use PublicInputHint::*;

        let segments = execution_info.memory_segments;
        let pedersen_segment = segments.pedersen.expect("layout requires Pedersen");
        let rc_segment = segments.range_check.expect("layout requires range check");
        let ecdsa_segment = segments.ecdsa.expect("layout requires ECDSA");
        let bitwise_segment = segments.bitwise.expect("layout requires bitwise");
        let ec_op_segment = segments.ec_op.expect("layout requires EC op");
        let poseidon_segment = segments.poseidon.expect("layout requires poseidon");

        let initial_perdersen_address = pedersen_segment.begin_addr.into();
        let initial_rc_address = rc_segment.begin_addr.into();
        let initial_ecdsa_address = ecdsa_segment.begin_addr.into();
        let initial_bitwise_address = bitwise_segment.begin_addr.into();
        let initial_ec_op_address = ec_op_segment.begin_addr.into();
        let initial_poseidon_address = poseidon_segment.begin_addr.into();

        let memory_quotient =
            utils::compute_public_memory_quotient::<PUBLIC_MEMORY_STEP, Self::Fp, Self::Fq>(
                challenges[MemoryPermutation::Z],
                challenges[MemoryPermutation::A],
                trace_len,
                &execution_info.public_memory,
                execution_info.public_memory_padding(),
            );

        let diluted_cumulative_val = compute_diluted_cumulative_value::<
            Fp,
            Fp,
            DILUTED_CHECK_N_BITS,
            DILUTED_CHECK_SPACING,
        >(
            challenges[DilutedCheckAggregation::Z],
            challenges[DilutedCheckAggregation::A],
        );

        // TODO: add validation on the AirPublicInput struct
        // assert!(range_check_min <= range_check_max);
        let initial_ap = execution_info.initial_ap().into();
        let final_ap = execution_info.final_ap().into();
        let initial_pc = execution_info.initial_pc().into();
        let final_pc = execution_info.final_pc().into();

        Hints::new(vec![
            (InitialAp.index(), initial_ap),
            (InitialPc.index(), initial_pc),
            (FinalAp.index(), final_ap),
            (FinalPc.index(), final_pc),
            // TODO: this is a wrong value. Must fix
            (MemoryQuotient.index(), memory_quotient),
            (RangeCheckProduct.index(), Fp::ONE),
            (RangeCheckMin.index(), execution_info.rc_min.into()),
            (RangeCheckMax.index(), execution_info.rc_max.into()),
            (DilutedCheckProduct.index(), Fp::ONE),
            (DilutedCheckFirst.index(), Fp::ZERO),
            (DilutedCheckCumulativeValue.index(), diluted_cumulative_val),
            (InitialPedersenAddr.index(), initial_perdersen_address),
            (InitialRcAddr.index(), initial_rc_address),
            (InitialEcdsaAddr.index(), initial_ecdsa_address),
            (InitialBitwiseAddr.index(), initial_bitwise_address),
            (InitialEcOpAddr.index(), initial_ec_op_address),
            (InitialPoseidonAddr.index(), initial_poseidon_address),
        ])
    }
}

/// Cairo flag
/// https://eprint.iacr.org/2021/1063.pdf section 9
#[derive(Clone, Copy, EnumIter, PartialEq, Eq)]
pub enum Flag {
    // Group: [FlagGroup::DstReg]
    DstReg = 0,

    // Group: [FlagGroup::Op0]
    Op0Reg = 1,

    // Group: [FlagGroup::Op1Src]
    Op1Imm = 2,
    Op1Fp = 3,
    Op1Ap = 4,

    // Group: [FlagGroup::ResLogic]
    ResAdd = 5,
    ResMul = 6,

    // Group: [FlagGroup::PcUpdate]
    PcJumpAbs = 7,
    PcJumpRel = 8,
    PcJnz = 9,

    // Group: [FlagGroup::ApUpdate]
    ApAdd = 10,
    ApAdd1 = 11,

    // Group: [FlagGroup::Opcode]
    OpcodeCall = 12,
    OpcodeRet = 13,
    OpcodeAssertEq = 14,

    // 0 - padding to make flag cells a power-of-2
    Zero = 15,
}

impl From<Flag> for binary::Flag {
    fn from(value: Flag) -> Self {
        match value {
            Flag::DstReg => Self::DstReg,
            Flag::Op0Reg => Self::Op0Reg,
            Flag::Op1Imm => Self::Op1Imm,
            Flag::Op1Fp => Self::Op1Fp,
            Flag::Op1Ap => Self::Op1Ap,
            Flag::ResAdd => Self::ResAdd,
            Flag::ResMul => Self::ResMul,
            Flag::PcJumpAbs => Self::PcJumpAbs,
            Flag::PcJumpRel => Self::PcJumpRel,
            Flag::PcJnz => Self::PcJnz,
            Flag::ApAdd => Self::ApAdd,
            Flag::ApAdd1 => Self::ApAdd1,
            Flag::OpcodeCall => Self::OpcodeCall,
            Flag::OpcodeRet => Self::OpcodeRet,
            Flag::OpcodeAssertEq => Self::OpcodeAssertEq,
            Flag::Zero => Self::Zero,
        }
    }
}

impl ExecutionTraceColumn for Flag {
    fn index(&self) -> usize {
        0
    }

    fn offset<T>(&self, cycle_offset: isize) -> Expr<AlgebraicItem<T>> {
        use AlgebraicItem::Trace;
        // Get the individual bit (as opposed to the bit prefix)
        let col = self.index();
        let trace_offset = CYCLE_HEIGHT as isize * cycle_offset;
        let flag_offset = trace_offset + *self as isize;
        Expr::from(Trace(col, flag_offset))
            - (Trace(col, flag_offset + 1) + Trace(col, flag_offset + 1))
    }
}

#[derive(Clone, Copy)]
pub enum RangeCheckBuiltin {
    Rc16Component = 12,
}

impl ExecutionTraceColumn for RangeCheckBuiltin {
    fn index(&self) -> usize {
        7
    }

    fn offset<T>(&self, offset: isize) -> Expr<AlgebraicItem<T>> {
        let column = self.index();
        let step = RANGE_CHECK_BUILTIN_RATIO * CYCLE_HEIGHT / RANGE_CHECK_BUILTIN_PARTS;
        let trace_offset = match self {
            Self::Rc16Component => step as isize * offset + *self as isize,
        };
        AlgebraicItem::Trace(column, trace_offset).into()
    }
}

#[derive(Clone, Copy)]
pub enum Poseidon {
    FullRoundsState0,
    FullRoundsState0Squared,
    FullRoundsState1,
    FullRoundsState1Squared,
    FullRoundsState2,
    FullRoundsState2Squared,
    PartialRoundsState0,
    PartialRoundsState0Squared,
    PartialRoundsState1,
    PartialRoundsState1Squared,
}

impl Poseidon {
    /// Output is of the form (col_idx, row_shift)
    pub const fn col_and_shift(&self) -> (usize, isize) {
        match self {
            Self::FullRoundsState0 => (8, 53),
            Self::FullRoundsState0Squared => (8, 29),
            Self::FullRoundsState1 => (8, 13),
            Self::FullRoundsState1Squared => (8, 61),
            Self::FullRoundsState2 => (8, 45),
            Self::FullRoundsState2Squared => (8, 3),
            Self::PartialRoundsState0 => (7, 3),
            Self::PartialRoundsState0Squared => (7, 7),
            Self::PartialRoundsState1 => (8, 6),
            Self::PartialRoundsState1Squared => (8, 14),
        }
    }
}

impl ExecutionTraceColumn for Poseidon {
    fn index(&self) -> usize {
        let (col_idx, _) = self.col_and_shift();
        col_idx
    }

    fn offset<T>(&self, offset: isize) -> Expr<AlgebraicItem<T>> {
        let (column, shift) = self.col_and_shift();
        let step = match self {
            Self::FullRoundsState0
            | Self::FullRoundsState0Squared
            | Self::FullRoundsState1
            | Self::FullRoundsState1Squared
            | Self::FullRoundsState2
            | Self::FullRoundsState2Squared => POSEIDON_RATIO * CYCLE_HEIGHT / POSEIDON_ROUNDS_FULL,
            Self::PartialRoundsState0 | Self::PartialRoundsState0Squared => {
                // TODO: symbol for 64?
                POSEIDON_RATIO * CYCLE_HEIGHT / 64
            }
            Self::PartialRoundsState1 | Self::PartialRoundsState1Squared => {
                POSEIDON_RATIO * CYCLE_HEIGHT / 32
            }
        } as isize;
        let trace_offset = step * offset + shift;
        AlgebraicItem::Trace(column, trace_offset).into()
    }
}

#[derive(Clone, Copy)]
pub enum EcOp {
    QDoublingX = 41,
    QDoublingY = 25,
    QDoublingSlope = 57,
    RPartialSumX = 5,
    RPartialSumY = 37,
    RPartialSumSlope = 11,
    RPartialSumXDiffInv = 43,
    MSuffix = 21,
    /// Repurposes the last [Ecdsa::PubkeyPartialSumXDiffInv]
    /// (which doesn't have a constraint)
    // NOTE: 16371 % 64 = 51
    MBit251AndBit196AndBit192 = 16371,
    /// Repurposes the last [Ecdsa::PubkeyPartialSumSlope]
    /// (which doesn't have a constraint)
    // NOTE: 16339 % 64 = 19
    MBit251AndBit196 = 16339,
}

impl ExecutionTraceColumn for EcOp {
    fn index(&self) -> usize {
        match self {
            Self::QDoublingX
            | Self::QDoublingY
            | Self::QDoublingSlope
            | Self::MSuffix
            | Self::MBit251AndBit196AndBit192
            | Self::MBit251AndBit196
            | Self::RPartialSumX
            | Self::RPartialSumY
            | Self::RPartialSumSlope
            | Self::RPartialSumXDiffInv => 8,
        }
    }

    fn offset<T>(&self, offset: isize) -> Expr<AlgebraicItem<T>> {
        let column = self.index();
        let step = match self {
            Self::QDoublingX
            | Self::QDoublingY
            | Self::QDoublingSlope
            | Self::MSuffix
            | Self::MBit251AndBit196AndBit192
            | Self::MBit251AndBit196
            | Self::RPartialSumX
            | Self::RPartialSumY
            | Self::RPartialSumSlope
            | Self::RPartialSumXDiffInv => EC_OP_BUILTIN_RATIO * CYCLE_HEIGHT / EC_OP_SCALAR_HEIGHT,
        } as isize;
        let trace_offset = step * offset + *self as isize;
        AlgebraicItem::Trace(column, trace_offset).into()
    }
}

#[derive(Clone, Copy)]
pub enum Ecdsa {
    PubkeyDoublingX = 1,
    PubkeyDoublingY = 33,
    PubkeyDoublingSlope = 35,
    PubkeyPartialSumX = 17,
    PubkeyPartialSumY = 49,
    PubkeyPartialSumXDiffInv = 51,
    PubkeyPartialSumSlope = 19,
    RSuffix = 9,
    MessageSuffix = 59,
    GeneratorPartialSumY = 91,
    GeneratorPartialSumX = 27,
    GeneratorPartialSumXDiffInv = 7,
    GeneratorPartialSumSlope = 123,
    // NOTE: 16331 % 64 = 11
    // NOTE: 32715 % 64 = 11
    RPointSlope = 16331,
    RPointXDiffInv = 32715,
    // NOTE: 16355 % 64 = 35
    // NOTE: 32739 % 64 = 35
    RInv = 16355,
    WInv = 32739,
    // NOTE: 16363 % 64 = 43
    // NOTE: 32747 % 64 = 43
    MessageInv = 16363,
    PubkeyXSquared = 32747,
    // NOTE: 32763 % 128 = 123
    // NOTE: 32647 % 128 = 7
    BSlope = 32763,
    BXDiffInv = 32647,
}

impl ExecutionTraceColumn for Ecdsa {
    fn index(&self) -> usize {
        match self {
            Self::PubkeyDoublingX
            | Self::PubkeyDoublingY
            | Self::PubkeyPartialSumX
            | Self::PubkeyPartialSumY
            | Self::PubkeyPartialSumXDiffInv
            | Self::PubkeyPartialSumSlope
            | Self::RSuffix
            | Self::MessageSuffix
            | Self::PubkeyDoublingSlope
            | Self::GeneratorPartialSumY
            | Self::GeneratorPartialSumX
            | Self::GeneratorPartialSumXDiffInv
            | Self::GeneratorPartialSumSlope
            | Self::RPointSlope
            | Self::RPointXDiffInv
            | Self::PubkeyXSquared
            | Self::MessageInv
            | Self::BSlope
            | Self::BXDiffInv
            | Self::RInv
            | Self::WInv => 8,
        }
    }

    fn offset<T>(&self, offset: isize) -> Expr<AlgebraicItem<T>> {
        let column = self.index();
        let step = match self {
            Self::PubkeyDoublingX
            | Self::PubkeyDoublingY
            | Self::PubkeyDoublingSlope
            | Self::RSuffix
            | Self::PubkeyPartialSumX
            | Self::PubkeyPartialSumY
            | Self::PubkeyPartialSumXDiffInv
            | Self::PubkeyPartialSumSlope => {
                EC_OP_BUILTIN_RATIO * CYCLE_HEIGHT / EC_OP_SCALAR_HEIGHT
            }
            Self::MessageSuffix
            | Self::GeneratorPartialSumX
            | Self::GeneratorPartialSumY
            | Self::GeneratorPartialSumSlope
            | Self::GeneratorPartialSumXDiffInv => {
                ECDSA_BUILTIN_RATIO * CYCLE_HEIGHT / EC_OP_SCALAR_HEIGHT
            }
            Self::RPointSlope
            | Self::RPointXDiffInv
            | Self::PubkeyXSquared
            | Self::MessageInv
            | Self::BSlope
            | Self::BXDiffInv
            | Self::RInv
            | Self::WInv => ECDSA_BUILTIN_RATIO * CYCLE_HEIGHT,
        } as isize;
        let trace_offset = step * offset + *self as isize;
        AlgebraicItem::Trace(column, trace_offset).into()
    }
}

#[derive(Clone, Copy)]
pub enum Bitwise {
    // TODO: better names or just don't use this
    // for 1st chunk 64 bits
    Bits16Chunk0Offset0 = 1,
    Bits16Chunk0Offset1 = 17,
    Bits16Chunk0Offset2 = 33,
    Bits16Chunk0Offset3 = 49,
    // for 2nd chunk of 64 bits
    Bits16Chunk1Offset0 = 65,
    Bits16Chunk1Offset1 = 81,
    Bits16Chunk1Offset2 = 97,
    Bits16Chunk1Offset3 = 113,
    // for 3rd chunk of 64 bits
    Bits16Chunk2Offset0 = 129,
    Bits16Chunk2Offset1 = 145,
    Bits16Chunk2Offset2 = 161,
    Bits16Chunk2Offset3 = 177,
    // for 4th chunk of 64 bits
    Bits16Chunk3Offset0 = 193,
    Bits16Chunk3Offset1 = 209,
    Bits16Chunk3Offset2 = 225,
    Bits16Chunk3Offset3 = 241,
    // these fields hold shifted values to ensure
    // that there has been a unique unpacking
    // NOTE: 8/8 = 1
    // NOTE: 0 = 2^5 * 0
    Bits16Chunk3Offset0ResShifted = 9,
    // NOTE: 520/8 = 65
    // NOTE: 64 = 2^5 * 2
    Bits16Chunk3Offset1ResShifted = 521,
    // NOTE: 264/8 = 33
    // NOTE: 64 = 2^5 * 1
    Bits16Chunk3Offset2ResShifted = 265,
    // NOTE: 776/8 = 97
    // NOTE: 64 = 2^5 * 3
    Bits16Chunk3Offset3ResShifted = 777,
}

impl ExecutionTraceColumn for Bitwise {
    fn index(&self) -> usize {
        match self {
            Self::Bits16Chunk0Offset0
            | Self::Bits16Chunk0Offset1
            | Self::Bits16Chunk0Offset2
            | Self::Bits16Chunk0Offset3
            | Self::Bits16Chunk1Offset0
            | Self::Bits16Chunk1Offset1
            | Self::Bits16Chunk1Offset2
            | Self::Bits16Chunk1Offset3
            | Self::Bits16Chunk2Offset0
            | Self::Bits16Chunk2Offset1
            | Self::Bits16Chunk2Offset2
            | Self::Bits16Chunk2Offset3
            | Self::Bits16Chunk3Offset0
            | Self::Bits16Chunk3Offset1
            | Self::Bits16Chunk3Offset2
            | Self::Bits16Chunk3Offset3
            | Self::Bits16Chunk3Offset0ResShifted
            | Self::Bits16Chunk3Offset1ResShifted
            | Self::Bits16Chunk3Offset2ResShifted
            | Self::Bits16Chunk3Offset3ResShifted => 7,
        }
    }

    fn offset<T>(&self, offset: isize) -> Expr<AlgebraicItem<T>> {
        let column = self.index();
        let step = match self {
            Self::Bits16Chunk0Offset0
            | Self::Bits16Chunk0Offset1
            | Self::Bits16Chunk0Offset2
            | Self::Bits16Chunk0Offset3
            | Self::Bits16Chunk1Offset0
            | Self::Bits16Chunk1Offset1
            | Self::Bits16Chunk1Offset2
            | Self::Bits16Chunk1Offset3
            | Self::Bits16Chunk2Offset0
            | Self::Bits16Chunk2Offset1
            | Self::Bits16Chunk2Offset2
            | Self::Bits16Chunk2Offset3
            | Self::Bits16Chunk3Offset0
            | Self::Bits16Chunk3Offset1
            | Self::Bits16Chunk3Offset2
            | Self::Bits16Chunk3Offset3 => 256,
            Self::Bits16Chunk3Offset0ResShifted
            | Self::Bits16Chunk3Offset1ResShifted
            | Self::Bits16Chunk3Offset2ResShifted
            | Self::Bits16Chunk3Offset3ResShifted => 1024,
        };
        AlgebraicItem::Trace(column, offset * step + *self as isize).into()
    }
}

#[derive(Clone, Copy)]
pub enum Pedersen {
    PartialSumX,
    PartialSumY,
    Suffix,
    Slope,
    Bit251AndBit196AndBit192 = 71,
    Bit251AndBit196 = 255,
}

impl ExecutionTraceColumn for Pedersen {
    fn index(&self) -> usize {
        match self {
            Self::PartialSumX => 1,
            Self::PartialSumY => 2,
            Self::Suffix => 3,
            Self::Slope | Self::Bit251AndBit196 => 4,
            Self::Bit251AndBit196AndBit192 => 8,
        }
    }

    fn offset<T>(&self, offset: isize) -> Expr<AlgebraicItem<T>> {
        let column = self.index();
        let trace_offset = match self {
            Self::PartialSumX | Self::PartialSumY | Self::Suffix | Self::Slope => offset,
            Self::Bit251AndBit196AndBit192 | Self::Bit251AndBit196 => {
                (PEDERSEN_BUILTIN_RATIO * CYCLE_HEIGHT / 2) as isize * offset + *self as isize
            }
        };
        AlgebraicItem::Trace(column, trace_offset).into()
    }
}

// NPC? not sure what it means yet - next program counter?
// Trace column 5
// Perhaps control flow is a better name for this column
#[derive(Clone, Copy)]
pub enum Npc {
    // TODO: first word of each instruction?
    Pc = 0, // Program counter
    Instruction = 1,
    PubMemAddr = 2,
    PubMemVal = 3,
    MemOp0Addr = 4,
    MemOp0 = 5,

    PedersenInput0Addr = 6,
    PedersenInput0Val = 7,

    // 262 % 16 = 6
    // 263 % 16 = 7
    PedersenInput1Addr = 262,
    PedersenInput1Val = 263,

    // 134 % 16 = 6
    // 135 % 16 = 7
    PedersenOutputAddr = 134,
    PedersenOutputVal = 135,

    // 70 % 16 = 6
    // 71 % 16 = 7
    RangeCheck128Addr = 70,
    RangeCheck128Val = 71,

    // 390 % 16 = 6
    // 391 % 16 = 7
    EcdsaPubkeyAddr = 390,
    EcdsaPubkeyVal = 391,

    // 16774 % 16 = 6
    // 16775 % 16 = 7
    EcdsaMessageAddr = 16774,
    EcdsaMessageVal = 16775,

    // 198 % 16 = 6
    // 199 % 16 = 7
    BitwisePoolAddr = 198,
    BitwisePoolVal = 199,

    // 902 % 16 = 6
    // 903 % 16 = 7
    BitwiseXOrYAddr = 902,
    BitwiseXOrYVal = 903,

    // 8582 % 16 = 6
    // 8583 % 16 = 7
    EcOpPXAddr = 8582,
    EcOpPXVal = 8583,

    // 4486 % 16 = 6
    // 4487 % 16 = 7
    EcOpPYAddr = 4486,
    EcOpPYVal = 4487,

    // 12678 % 16 = 6
    // 12679 % 16 = 7
    EcOpQXAddr = 12678,
    EcOpQXVal = 12679,

    // 2438 % 16 = 6
    // 2439 % 16 = 7
    EcOpQYAddr = 2438,
    EcOpQYVal = 2439,

    // 10630 % 16 = 6
    // 10631 % 16 = 7
    EcOpMAddr = 10630,
    EcOpMVal = 10631,

    // 6534 % 16 = 6
    // 6535 % 16 = 7
    EcOpRXAddr = 6534,
    EcOpRXVal = 6535,

    // 14726 % 16 = 6
    // 14727 % 16 = 7
    EcOpRYAddr = 14726,
    EcOpRYVal = 14727,

    // 38 % 16 = 6
    // 39 % 16 = 7
    PoseidonInput0Addr = 38,
    PoseidonInput0Val = 39,

    // 102 % 16 = 6
    // 103 % 16 = 7
    PoseidonInput1Addr = 102,
    PoseidonInput1Val = 103,

    // 166 % 16 = 6
    // 167 % 16 = 7
    PoseidonInput2Addr = 166,
    PoseidonInput2Val = 167,

    // 230 % 16 = 6
    // 231 % 16 = 7
    PoseidonOutput0Addr = 230,
    PoseidonOutput0Val = 231,

    // 294 % 16 = 6
    // 295 % 16 = 7
    PoseidonOutput1Addr = 294,
    PoseidonOutput1Val = 295,

    // 358 % 16 = 6
    // 359 % 16 = 7
    PoseidonOutput2Addr = 358,
    PoseidonOutput2Val = 359,

    MemDstAddr = 8,
    MemDst = 9,
    // NOTE: cycle cells 10 and 11 is occupied by PubMemAddr since the public memory step is 8.
    // This means it applies twice (2, 3) then (8+2, 8+3) within a single 16 row cycle.
    MemOp1Addr = 12,
    MemOp1 = 13,

    UnusedAddr = 14,
    UnusedVal = 15,
}

impl ExecutionTraceColumn for Npc {
    fn index(&self) -> usize {
        5
    }

    fn offset<T>(&self, offset: isize) -> Expr<AlgebraicItem<T>> {
        let step = match self {
            Self::PubMemAddr | Self::PubMemVal => PUBLIC_MEMORY_STEP,
            Self::PedersenInput0Addr
            | Self::PedersenInput0Val
            | Self::PedersenInput1Addr
            | Self::PedersenInput1Val
            | Self::PedersenOutputAddr
            | Self::PedersenOutputVal => CYCLE_HEIGHT * PEDERSEN_BUILTIN_RATIO,
            Self::RangeCheck128Addr | Self::RangeCheck128Val => {
                CYCLE_HEIGHT * RANGE_CHECK_BUILTIN_RATIO
            }
            Self::EcdsaMessageAddr
            | Self::EcdsaPubkeyAddr
            | Self::EcdsaMessageVal
            | Self::EcdsaPubkeyVal => CYCLE_HEIGHT * ECDSA_BUILTIN_RATIO,
            Self::Pc
            | Self::Instruction
            | Self::MemOp0Addr
            | Self::MemOp0
            | Self::MemDstAddr
            | Self::MemDst
            | Self::MemOp1Addr
            | Self::UnusedAddr
            | Self::UnusedVal
            | Self::MemOp1 => CYCLE_HEIGHT,
            Self::BitwisePoolAddr | Self::BitwisePoolVal => BITWISE_RATIO * CYCLE_HEIGHT / 4,
            Self::BitwiseXOrYAddr | Self::BitwiseXOrYVal => BITWISE_RATIO * CYCLE_HEIGHT,
            Self::EcOpPXAddr
            | Self::EcOpPXVal
            | Self::EcOpPYAddr
            | Self::EcOpPYVal
            | Self::EcOpQXAddr
            | Self::EcOpQXVal
            | Self::EcOpQYAddr
            | Self::EcOpQYVal
            | Self::EcOpMAddr
            | Self::EcOpMVal
            | Self::EcOpRXAddr
            | Self::EcOpRXVal
            | Self::EcOpRYAddr
            | Self::EcOpRYVal => EC_OP_BUILTIN_RATIO * CYCLE_HEIGHT,
            Self::PoseidonInput0Addr
            | Self::PoseidonInput0Val
            | Self::PoseidonInput1Addr
            | Self::PoseidonInput1Val
            | Self::PoseidonInput2Addr
            | Self::PoseidonInput2Val
            | Self::PoseidonOutput0Addr
            | Self::PoseidonOutput0Val
            | Self::PoseidonOutput1Addr
            | Self::PoseidonOutput1Val
            | Self::PoseidonOutput2Addr
            | Self::PoseidonOutput2Val => POSEIDON_RATIO * CYCLE_HEIGHT,
        } as isize;
        let column = self.index();
        let trace_offset = step * offset + *self as isize;
        AlgebraicItem::Trace(column, trace_offset).into()
    }
}

impl CairoAirConfig for AirConfig {
    fn public_memory_challenges(challenges: &Challenges<Self::Fq>) -> (Self::Fq, Self::Fq) {
        (
            challenges[MemoryPermutation::Z],
            challenges[MemoryPermutation::A],
        )
    }

    fn public_memory_quotient(hints: &Hints<Self::Fq>) -> Self::Fq {
        hints[PublicInputHint::MemoryQuotient]
    }
}

// Trace column 6 - memory
#[derive(Clone, Copy)]
pub enum Mem {
    // TODO = 0,
    Address = 0,
    Value = 1,
}

impl ExecutionTraceColumn for Mem {
    fn index(&self) -> usize {
        6
    }

    fn offset<T>(&self, mem_offset: isize) -> Expr<AlgebraicItem<T>> {
        let column = self.index();
        let trace_offset = MEMORY_STEP as isize * mem_offset + *self as isize;
        AlgebraicItem::Trace(column, trace_offset).into()
    }
}

#[derive(Clone, Copy)]
pub enum DilutedCheck {
    Unordered = 1,
    Ordered = 5,
    Aggregate = 3,
}

impl ExecutionTraceColumn for DilutedCheck {
    fn index(&self) -> usize {
        match self {
            Self::Unordered | Self::Ordered => 7,
            Self::Aggregate => 9,
        }
    }

    fn offset<T>(&self, offset: isize) -> Expr<AlgebraicItem<T>> {
        let column = self.index();
        AlgebraicItem::Trace(column, 8 * offset + *self as isize).into()
    }
}

// Trace column 7
#[derive(Clone, Copy)]
pub enum RangeCheck {
    OffDst = 0,
    Ordered = 2, // Stores ordered values for the range check
    // TODO 2
    OffOp1 = 4,
    // Ordered = 6 - trace step is 4
    OffOp0 = 8,
    // Ordered = 10 - trace step is 4
    // This cell alternates cycle to cycle between:
    // - Being used for the 128 bit range checks builtin - even cycles
    // - Filled with padding to fill any gaps - odd cycles
    Unused = 12,
    // Ordered = 14 - trace step is 4
}

impl ExecutionTraceColumn for RangeCheck {
    fn index(&self) -> usize {
        7
    }

    fn offset<T>(&self, cycle_offset: isize) -> Expr<AlgebraicItem<T>> {
        let step = match self {
            RangeCheck::Ordered => RANGE_CHECK_STEP,
            _ => CYCLE_HEIGHT,
        } as isize;
        let column = self.index();
        let trace_offset = step * cycle_offset + *self as isize;
        AlgebraicItem::Trace(column, trace_offset).into()
    }
}

// Auxiliary column 8
#[derive(Clone, Copy)]
pub enum Auxiliary {
    Ap = 0, // Allocation pointer (ap)
    Tmp0 = 2,
    Op0MulOp1 = 4, // =op0*op1
    Fp = 8,        // Frame pointer (fp)
    Tmp1 = 10,
    Res = 12,
}

impl ExecutionTraceColumn for Auxiliary {
    fn index(&self) -> usize {
        8
    }

    fn offset<T>(&self, cycle_offset: isize) -> Expr<AlgebraicItem<T>> {
        let column = self.index();
        let step = match self {
            Self::Ap | Self::Fp | Self::Tmp0 | Self::Tmp1 | Self::Op0MulOp1 | Self::Res => {
                CYCLE_HEIGHT
            }
        } as isize;
        let trace_offset = step * cycle_offset + *self as isize;
        AlgebraicItem::Trace(column, trace_offset).into()
    }
}

// Trace column 6 - permutations
#[derive(Clone, Copy)]
pub enum Permutation {
    // TODO = 0,
    Memory = 0,
    RangeCheck = 1,
    DilutedCheck = 7,
}

impl ExecutionTraceColumn for Permutation {
    fn index(&self) -> usize {
        9
    }

    fn offset<T>(&self, offset: isize) -> Expr<AlgebraicItem<T>> {
        let column = self.index();
        let trace_offset = match self {
            Self::Memory => MEMORY_STEP as isize * offset + *self as isize,
            Self::RangeCheck => 4 * offset + *self as isize,
            Self::DilutedCheck => 8 * offset + *self as isize,
        };
        AlgebraicItem::Trace(column, trace_offset).into()
    }
}

#[derive(Clone, Copy)]
pub enum PublicInputHint {
    InitialAp,
    InitialPc,
    FinalAp,
    FinalPc,
    MemoryQuotient, // TODO
    RangeCheckProduct,
    RangeCheckMin,
    RangeCheckMax,
    DilutedCheckProduct,
    DilutedCheckFirst,
    DilutedCheckCumulativeValue,
    InitialPedersenAddr,
    InitialRcAddr,
    InitialEcdsaAddr,
    InitialBitwiseAddr,
    InitialEcOpAddr,
    InitialPoseidonAddr,
}

impl Hint for PublicInputHint {
    fn index(&self) -> usize {
        *self as usize
    }
}

/// Symbolic memory permutation challenges
/// Note section 9.7.2 from Cairo whitepaper
/// (z − (address + α * value))
#[derive(Clone, Copy)]
pub enum MemoryPermutation {
    Z = 0, // =z
    A = 1, // =α
}

impl VerifierChallenge for MemoryPermutation {
    fn index(&self) -> usize {
        *self as usize
    }
}

/// Symbolic range check permutation challenges
/// Note section 9.7.2 from Cairo whitepaper
/// (z − value)
#[derive(Clone, Copy)]
pub enum RangeCheckPermutation {
    Z = 2, // =z
}

impl VerifierChallenge for RangeCheckPermutation {
    fn index(&self) -> usize {
        *self as usize
    }
}

/// Symbolic diluted check permutation challenges
#[derive(Clone, Copy)]
pub enum DilutedCheckPermutation {
    Z = 3, // =z
}

impl VerifierChallenge for DilutedCheckPermutation {
    fn index(&self) -> usize {
        *self as usize
    }
}

/// Symbolic diluted check aggregation challenges
#[derive(Clone, Copy)]
pub enum DilutedCheckAggregation {
    Z = 4, // =z
    A = 5, // =α
}

impl VerifierChallenge for DilutedCheckAggregation {
    fn index(&self) -> usize {
        *self as usize
    }
}
