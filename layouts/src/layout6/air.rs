use super::CYCLE_HEIGHT;
use super::MEMORY_STEP;
use super::PEDERSEN_BUILTIN_RATIO;
use super::PUBLIC_MEMORY_STEP;
use super::RANGE_CHECK_BUILTIN_PARTS;
use super::RANGE_CHECK_BUILTIN_RATIO;
use super::RANGE_CHECK_STEP;
use crate::utils;
use crate::ExecutionInfo;
use ark_poly::EvaluationDomain;
use ark_poly::Radix2EvaluationDomain;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use core::ops::Add;
use core::ops::Mul;
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
use num_traits::Zero;
use strum_macros::EnumIter;

pub struct AirConfig;

impl ministark::air::AirConfig for AirConfig {
    const NUM_BASE_COLUMNS: usize = 9;
    const NUM_EXTENSION_COLUMNS: usize = 1;
    type Fp = Fp;
    type Fq = Fp;
    type PublicInputs = ExecutionInfo<Fp>;

    fn constraints(trace_len: usize) -> Vec<Constraint<FieldVariant<Fp, Fp>>> {
        use AlgebraicItem::*;
        use PublicInputHint::*;
        // TODO: figure out why this value
        let n = trace_len;
        let trace_domain = Radix2EvaluationDomain::<Fp>::new(n).unwrap();
        let g = trace_domain.group_gen();
        assert!(n >= CYCLE_HEIGHT, "must be a multiple of cycle height");
        let x = Expr::from(X);
        let one = Expr::from(Constant(FieldVariant::Fp(Fp::ONE)));
        let two = Expr::from(Constant(FieldVariant::Fp(Fp::from(2u32))));
        let four = Expr::from(Constant(FieldVariant::Fp(Fp::from(4u32))));
        let offset_size = Expr::from(Constant(FieldVariant::Fp(Fp::from(2u32.pow(16)))));
        let half_offset_size = Expr::from(Constant(FieldVariant::Fp(Fp::from(2u32.pow(15)))));

        // cpu/decode/flag_op1_base_op0_0
        let cpu_decode_flag_op1_base_op0_0: Expr<AlgebraicItem<FieldVariant<Fp, Fp>>> =
            &one - (Flag::Op1Imm.curr() + Flag::Op1Ap.curr() + Flag::Op1Fp.curr());
        // cpu/decode/flag_res_op1_0
        let cpu_decode_flag_res_op1_0: Expr<AlgebraicItem<FieldVariant<Fp, Fp>>> =
            &one - (Flag::ResAdd.curr() + Flag::ResMul.curr() + Flag::PcJnz.curr());
        // cpu/decode/flag_pc_update_regular_0
        let cpu_decode_flag_pc_update_regular_0: Expr<AlgebraicItem<FieldVariant<Fp, Fp>>> =
            &one - (Flag::PcJumpAbs.curr() + Flag::PcJumpRel.curr() + Flag::PcJnz.curr());
        // cpu/decode/fp_update_regular_0
        let cpu_decode_fp_update_regular_0: Expr<AlgebraicItem<FieldVariant<Fp, Fp>>> =
            &one - (Flag::OpcodeCall.curr() + Flag::OpcodeRet.curr());

        // NOTE: npc_reg_0 = pc + instruction_size
        // NOTE: instruction_size = fOP1_IMM + 1
        let npc_reg_0 = Npc::Pc.curr() + Flag::Op1Imm.curr() + &one;

        let memory_address_diff_0: Expr<AlgebraicItem<FieldVariant<Fp, Fp>>> =
            Mem::Address.next() - Mem::Address.curr();

        let rc16_diff_0: Expr<AlgebraicItem<FieldVariant<Fp, Fp>>> =
            RangeCheck::Ordered.next() - RangeCheck::Ordered.curr();

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
        let _ecdsa_sig0_doubling_key_x_squared: Expr<AlgebraicItem<FieldVariant<Fp, Fp>>> =
            Trace(8, 4) * Trace(8, 4);
        let ecdsa_sig0_exponentiate_generator_b0 =
            Expr::from(Trace(8, 34)) - (Trace(8, 162) + Trace(8, 162));
        let _ecdsa_sig0_exponentiate_generator_b0_neg = &one - ecdsa_sig0_exponentiate_generator_b0;
        let ecdsa_sig0_exponentiate_key_b0 =
            Expr::from(Trace(8, 12)) - (Trace(8, 76) + Trace(8, 76));
        let _ecdsa_sig0_exponentiate_key_b0_neg = &one - &ecdsa_sig0_exponentiate_key_b0;
        let _bitwise_sum_var_0_0: Expr<AlgebraicItem<FieldVariant<Fp, Fp>>> =
            Expr::from(Trace(7, 1))
                + Expr::from(Trace(7, 17)) * (&two).pow(1)
                + Expr::from(Trace(7, 33)) * (&two).pow(2)
                + Expr::from(Trace(7, 49)) * (&two).pow(3)
                + Expr::from(Trace(7, 65)) * (&two).pow(64)
                + Expr::from(Trace(7, 81)) * (&two).pow(65)
                + Expr::from(Trace(7, 97)) * (&two).pow(66)
                + Expr::from(Trace(7, 113)) * (&two).pow(67);
        let _bitwise_sum_var_8_0: Expr<AlgebraicItem<FieldVariant<Fp, Fp>>> =
            Expr::from(Trace(7, 129)) * (&two).pow(129)
                + Expr::from(Trace(7, 145)) * (&two).pow(130)
                + Expr::from(Trace(7, 161)) * (&two).pow(131)
                + Expr::from(Trace(7, 177)) * (&two).pow(132)
                + Expr::from(Trace(7, 193)) * (&two).pow(193)
                + Expr::from(Trace(7, 209)) * (&two).pow(194)
                + Expr::from(Trace(7, 255)) * (&two).pow(195)
                + Expr::from(Trace(7, 241)) * (&two).pow(196);

        // example for trace length n=64
        // =============================
        // x^(n/16)                 = (x - ω_0)(x - ω_16)(x - ω_32)(x - ω_48)
        // x^(n/16) - c             = (x - c*ω_0)(x - c*ω_16)(x - c*ω_32)(x - c*ω_48)
        // x^(n/16) - ω^(n/16)      = (x - ω_1)(x - ω_17)(x - ω_33)(x - ω_49)
        // x^(n/16) - ω^(n/16)^(15) = (x - ω_15)(x - ω_31)(x - ω_47)(x - ω_63)
        let flag0_offset =
            FieldVariant::Fp(g.pow([(Flag::Zero as usize * n / CYCLE_HEIGHT) as u64]));
        let flag0_zerofier = X.pow(n / CYCLE_HEIGHT) - Constant(flag0_offset);
        let flags_zerofier = &flag0_zerofier / (X.pow(n) - &one);

        // check decoded flag values are 0 or 1
        // NOTE: This expression is a bit confusing. The zerofier forces this constraint
        // to apply in all rows of the trace therefore it applies to all flags (not just
        // DstReg). Funnily enough any flag here would work (it just wouldn't be SHARP
        // compatible).
        let cpu_decode_opcode_rc_b =
            (Flag::DstReg.curr() * Flag::DstReg.curr() - Flag::DstReg.curr()) * &flags_zerofier;

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
        let cpu_decode_opcode_rc_input = (Npc::Instruction.curr()
            - (((&whole_flag_prefix * &offset_size + RangeCheck::OffOp1.curr()) * &offset_size
                + RangeCheck::OffOp0.curr())
                * &offset_size
                + RangeCheck::OffDst.curr()))
            / &all_cycles_zerofier;

        // constraint for the Op1Src flag group - forces vals 000, 100, 010 or 001
        let cpu_decode_flag_op1_base_op0_bit = (&cpu_decode_flag_op1_base_op0_0
            * &cpu_decode_flag_op1_base_op0_0
            - &cpu_decode_flag_op1_base_op0_0)
            / &all_cycles_zerofier;

        // forces only one or none of ResAdd, ResMul or PcJnz to be 1
        // TODO: Why the F is PcJnz in here? Res flag group is only bit 5 and 6
        // NOTE: looks like it's a handy optimization to calculate next_fp and next_ap
        let cpu_decode_flag_res_op1_bit = (&cpu_decode_flag_res_op1_0 * &cpu_decode_flag_res_op1_0
            - &cpu_decode_flag_res_op1_0)
            / &all_cycles_zerofier;

        // constraint forces PcUpdate flag to be 000, 100, 010 or 001
        let cpu_decode_flag_pc_update_regular_bit = (&cpu_decode_flag_pc_update_regular_0
            * &cpu_decode_flag_pc_update_regular_0
            - &cpu_decode_flag_pc_update_regular_0)
            / &all_cycles_zerofier;

        // forces max only OpcodeRet or OpcodeAssertEq to be 1
        // TODO: why OpcodeCall not included? that would make whole flag group
        let cpu_decode_fp_update_regular_bit = (&cpu_decode_fp_update_regular_0
            * &cpu_decode_fp_update_regular_0
            - &cpu_decode_fp_update_regular_0)
            / &all_cycles_zerofier;

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
            - (Flag::DstReg.curr() * RangeCheck::Fp.curr()
                + (&one - Flag::DstReg.curr()) * RangeCheck::Ap.curr()
                + RangeCheck::OffDst.curr()))
            / &all_cycles_zerofier;

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
            - (Flag::Op0Reg.curr() * RangeCheck::Fp.curr()
                + (&one - Flag::Op0Reg.curr()) * RangeCheck::Ap.curr()
                + RangeCheck::OffOp0.curr()))
            / &all_cycles_zerofier;

        // NOTE: StarkEx contracts as: cpu_operands_mem1_addr
        let cpu_operands_mem_op1_addr = (Npc::MemOp1Addr.curr() + &half_offset_size
            - (Flag::Op1Imm.curr() * Npc::Pc.curr()
                + Flag::Op1Ap.curr() * RangeCheck::Ap.curr()
                + Flag::Op1Fp.curr() * RangeCheck::Fp.curr()
                + &cpu_decode_flag_op1_base_op0_0 * Npc::MemOp0.curr()
                + RangeCheck::OffOp1.curr()))
            / &all_cycles_zerofier;

        // op1 * op0
        // NOTE: starkex cpu/operands/ops_mul
        let cpu_operands_ops_mul = (RangeCheck::Op0MulOp1.curr()
            - Npc::MemOp0.curr() * Npc::MemOp1.curr())
            / &all_cycles_zerofier;

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
        let cpu_operands_res = ((&one - Flag::PcJnz.curr()) * RangeCheck::Res.curr()
            - (Flag::ResAdd.curr() * (Npc::MemOp0.curr() + Npc::MemOp1.curr())
                + Flag::ResMul.curr() * RangeCheck::Op0MulOp1.curr()
                + &cpu_decode_flag_res_op1_0 * Npc::MemOp1.curr()))
            / &all_cycles_zerofier;

        // example for trace length n=64
        // =============================
        // all_cycles_zerofier              = (x - ω_0)(x - ω_16)(x - ω_32)(x - ω_48)
        // X - ω^(16*(n/16 - 1))           = x - ω^n/w^16 = x - 1/w_16 = x - w_48
        // (X - w_48) / all_cycles_zerofier = (x - ω_0)(x - ω_16)(x - ω_32)
        let last_cycle_zerofier = X - Constant(FieldVariant::Fp(
            g.pow([(CYCLE_HEIGHT * (n / CYCLE_HEIGHT - 1)) as u64]),
        ));
        let all_cycles_except_last_zerofier = &last_cycle_zerofier / &all_cycles_zerofier;

        // Updating the program counter
        // ============================
        // This is not as straight forward as the other constraints. Read section 9.5
        // Updating pc to understand.

        // from whitepaper `t0 = fPC_JNZ * dst`
        let cpu_update_registers_update_pc_tmp0 = (Auxiliary::Tmp0.curr()
            - Flag::PcJnz.curr() * Npc::MemDst.curr())
            * &all_cycles_except_last_zerofier;

        // From the whitepaper "To verify that we make a regular update if dst = 0, we
        // need an auxiliary variable, v (to fill the trace in the case dst != 0, set v
        // = dst^(−1)): `fPC_JNZ * (dst * v − 1) * (next_pc − (pc + instruction_size)) =
        // 0` NOTE: if fPC_JNZ=1 then `res` is "unused" and repurposed as our
        // temporary variable `v`. The value assigned to v is `dst^(−1)`.
        // NOTE: `t1 = t0 * v`
        let cpu_update_registers_update_pc_tmp1 = (Auxiliary::Tmp1.curr()
            - Auxiliary::Tmp0.curr() * RangeCheck::Res.curr())
            * &all_cycles_except_last_zerofier;

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
                + Flag::PcJumpAbs.curr() * RangeCheck::Res.curr()
                + Flag::PcJumpRel.curr() * (Npc::Pc.curr() + RangeCheck::Res.curr())))
            * &all_cycles_except_last_zerofier;

        // ensure `if dst == 0: pc + instruction_size == next_pc`
        let cpu_update_registers_update_pc_pc_cond_positive =
            ((Auxiliary::Tmp1.curr() - Flag::PcJnz.curr()) * (Npc::Pc.next() - npc_reg_0))
                * &all_cycles_except_last_zerofier;

        // Updating the allocation pointer
        // ===============================
        // TODO: seems fishy don't see how `next_ap = ap + fAP_ADD · res + fAP_ADD1 · 1
        // + fOPCODE_CALL · 2` meets the pseudo code in the whitepaper
        // Ok, it does kinda make sense. move the `opcode == 1` statement inside and
        // move the switch to the outside and it's more clear.
        let cpu_update_registers_update_ap_ap_update = (RangeCheck::Ap.next()
            - (RangeCheck::Ap.curr()
                + Flag::ApAdd.curr() * RangeCheck::Res.curr()
                + Flag::ApAdd1.curr()
                + Flag::OpcodeCall.curr() * &two))
            * &all_cycles_except_last_zerofier;

        // Updating the frame pointer
        // ==========================
        // This handles all fp update except the `op0 == pc + instruction_size`, `res =
        // dst` and `dst == fp` assertions.
        // TODO: fix padding bug
        let cpu_update_registers_update_fp_fp_update = (RangeCheck::Fp.next()
            - (&cpu_decode_fp_update_regular_0 * RangeCheck::Fp.curr()
                + Flag::OpcodeRet.curr() * Npc::MemDst.curr()
                + Flag::OpcodeCall.curr() * (RangeCheck::Ap.curr() + &two)))
            * &all_cycles_except_last_zerofier;

        // push registers to memory (see section 8.4 in the whitepaper).
        // These are essentially the assertions for assert `op0 == pc +
        // instruction_size` and `assert dst == fp`.
        let cpu_opcodes_call_push_fp = (Flag::OpcodeCall.curr()
            * (Npc::MemDst.curr() - RangeCheck::Fp.curr()))
            / &all_cycles_zerofier;
        let cpu_opcodes_call_push_pc = (Flag::OpcodeCall.curr()
            * (Npc::MemOp0.curr() - (Npc::Pc.curr() + Flag::Op1Imm.curr() + &one)))
            / &all_cycles_zerofier;

        // make sure all offsets are valid for the call opcode
        // ===================================================
        // checks `if opcode == OpcodeCall: assert off_dst = 2^15`
        // this is supplementary to the constraints above because
        // offsets are in the range [-2^15, 2^15) encoded using
        // biased representation
        let cpu_opcodes_call_off0 = (Flag::OpcodeCall.curr()
            * (RangeCheck::OffDst.curr() - &half_offset_size))
            / &all_cycles_zerofier;
        // checks `if opcode == OpcodeCall: assert off_op0 = 2^15 + 1`
        // TODO: why +1?
        let cpu_opcodes_call_off1 = (Flag::OpcodeCall.curr()
            * (RangeCheck::OffOp0.curr() - (&half_offset_size + &one)))
            / &all_cycles_zerofier;
        // TODO: I don't understand this one - Flag::OpcodeCall.curr() is 0 or 1. Why
        // not just replace `Flag::OpcodeCall.curr() + Flag::OpcodeCall.curr() +
        // &one + &one` with `4`
        let cpu_opcodes_call_flags = (Flag::OpcodeCall.curr()
            * (Flag::OpcodeCall.curr() + Flag::OpcodeCall.curr() + &one + &one
                - (Flag::DstReg.curr() + Flag::Op0Reg.curr() + &four)))
            / &all_cycles_zerofier;
        // checks `if opcode == OpcodeRet: assert off_dst = 2^15 - 2`
        // TODO: why -2 🤯? Instruction size?
        let cpu_opcodes_ret_off0 = (Flag::OpcodeRet.curr()
            * (RangeCheck::OffDst.curr() + &two - &half_offset_size))
            / &all_cycles_zerofier;
        // checks `if opcode == OpcodeRet: assert off_op1 = 2^15 - 1`
        // TODO: why -1?
        let cpu_opcodes_ret_off2 = (Flag::OpcodeRet.curr()
            * (RangeCheck::OffOp1.curr() + &one - &half_offset_size))
            / &all_cycles_zerofier;
        // checks `if OpcodeRet: assert PcJumpAbs=1, DstReg=1, Op1Fp=1, ResLogic=0`
        let cpu_opcodes_ret_flags = (Flag::OpcodeRet.curr()
            * (Flag::PcJumpAbs.curr()
                + Flag::DstReg.curr()
                + Flag::Op1Fp.curr()
                + &cpu_decode_flag_res_op1_0
                - &four))
            / &all_cycles_zerofier;
        // handles the "assert equal" instruction. Represents this pseudo code from the
        // whitepaper `assert res = dst`.
        let cpu_opcodes_assert_eq_assert_eq = (Flag::OpcodeAssertEq.curr()
            * (Npc::MemDst.curr() - RangeCheck::Res.curr()))
            / &all_cycles_zerofier;

        let first_row_zerofier = &x - &one;

        // boundary constraint expression for initial registers
        let initial_ap = (RangeCheck::Ap.curr() - InitialAp.hint()) / &first_row_zerofier;
        let initial_fp = (RangeCheck::Fp.curr() - InitialAp.hint()) / &first_row_zerofier;
        let initial_pc = (Npc::Pc.curr() - InitialPc.hint()) / &first_row_zerofier;

        // boundary constraint expression for final registers
        let final_ap = (RangeCheck::Ap.curr() - FinalAp.hint()) / &last_cycle_zerofier;
        let final_fp = (RangeCheck::Fp.curr() - InitialAp.hint()) / &last_cycle_zerofier;
        let final_pc = (Npc::Pc.curr() - FinalPc.hint()) / &last_cycle_zerofier;

        // examples for trace length n=8
        // =============================
        // x^(n/2) - 1             = (x - ω_0)(x - ω_2)(x - ω_4)(x - ω_6)
        // x - ω^(2*(n/2 - 1))     = x - ω^n/w^2 = x - 1/w_2 = x - w_6
        // (x - w_6) / x^(n/2) - 1 = (x - ω_0)(x - ω_2)(x - ω_4)
        let every_second_row_zerofier = X.pow(n / 2) - &one;
        let second_last_row_zerofier =
            X - Constant(FieldVariant::Fp(g.pow([2 * (n as u64 / 2 - 1)])));
        let every_second_row_except_last_zerofier =
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
            / &first_row_zerofier;
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
            * &every_second_row_except_last_zerofier;
        // Check the last permutation value to verify public memory
        let memory_multi_column_perm_perm_last =
            (Permutation::Memory.curr() - MemoryProduct.hint()) / &second_last_row_zerofier;
        // Constraint expression for memory/diff_is_bit
        // checks the address doesn't change or increases by 1
        // "Continuity" constraint in cairo whitepaper 9.7.2
        let memory_diff_is_bit = (&memory_address_diff_0 * &memory_address_diff_0
            - &memory_address_diff_0)
            * &every_second_row_except_last_zerofier;
        // if the address stays the same then the value stays the same
        // "Single-valued" constraint in cairo whitepaper 9.7.2.
        // cairo uses nondeterministic read-only memory so if the address is the same
        // the value should also stay the same.
        let memory_is_func = ((&memory_address_diff_0 - &one)
            * (Mem::Value.curr() - Mem::Value.next()))
            * &every_second_row_except_last_zerofier;
        // boundary condition stating the first memory address == 1
        let memory_initial_addr = (Mem::Address.curr() - &one) / &first_row_zerofier;
        // applies every 8 rows
        let every_eighth_row_zerofier = X.pow(n / 8) - &one;
        // Read cairo whitepaper section 9.8 as to why the public memory cells are 0.
        // The high level is that the way public memory works is that the prover is
        // forced (with these constraints) to exclude the public memory from one of
        // the permutation products. This means the running permutation column
        // terminates with more-or-less the permutation of just the public input. The
        // verifier can relatively cheaply calculate this terminal. The constraint for
        // this terminal is `memory_multi_column_perm_perm_last`.
        let public_memory_addr_zero = Npc::PubMemAddr.curr() / &every_eighth_row_zerofier;
        let public_memory_value_zero = Npc::PubMemVal.curr() / &every_eighth_row_zerofier;

        // examples for trace length n=16
        // =====================================
        // x^(n/4) - 1              = (x - ω_0)(x - ω_4)(x - ω_8)(x - ω_12)
        // x - ω^(4*(n/4 - 1))      = x - ω^n/w^4 = x - 1/w_4 = x - w_12
        // (x - w_12) / x^(n/4) - 1 = (x - ω_0)(x - ω_4)(x - ω_8)
        let every_fourth_row_zerofier = X.pow(n / 4) - &one;
        let fourth_last_row_zerofier =
            X - Constant(FieldVariant::Fp(g.pow([4 * (n as u64 / 4 - 1)])));
        let every_fourth_row_except_last_zerofier =
            &fourth_last_row_zerofier / &every_fourth_row_zerofier;

        // Range check constraints
        // =======================
        // Look at memory to understand the general approach to permutation.
        // More info in section 9.9 of the Cairo paper.
        let rc16_perm_init0 = ((RangeCheckPermutation::Z.challenge() - RangeCheck::Ordered.curr())
            * Permutation::RangeCheck.curr()
            + RangeCheck::OffDst.curr()
            - RangeCheckPermutation::Z.challenge())
            / &first_row_zerofier;
        let rc16_perm_step0 = ((RangeCheckPermutation::Z.challenge() - RangeCheck::Ordered.next())
            * Permutation::RangeCheck.next()
            - (RangeCheckPermutation::Z.challenge() - RangeCheck::OffOp1.curr())
                * Permutation::RangeCheck.curr())
            * &every_fourth_row_except_last_zerofier;
        let rc16_perm_last =
            (Permutation::RangeCheck.curr() - RangeCheckProduct.hint()) / &fourth_last_row_zerofier;
        // Check the value increases by 0 or 1
        let rc16_diff_is_bit =
            (&rc16_diff_0 * &rc16_diff_0 - &rc16_diff_0) * &every_fourth_row_except_last_zerofier;
        // Prover sends the minimim and maximum as a public input.
        // Verifier checks the RC min and max fall within [0, 2^16).
        let rc16_minimum =
            (RangeCheck::Ordered.curr() - RangeCheckMin.hint()) / &first_row_zerofier;
        let rc16_maximum =
            (RangeCheck::Ordered.curr() - RangeCheckMax.hint()) / &fourth_last_row_zerofier;

        // TODO: find out what diluted constraints are for. Might be starkex specific

        // Pedersen builtin
        // ================
        // Each hash spans across 256 rows - that's one hash per 16 cairo steps.
        let every_256_row_zerofier = X.pow(n / 256) - &one;

        // These first few pedersen constraints check that the number is in the range
        // 100000000000000000000000000000000000000000000000000000010001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001

        // pedersen/hash0/ec_subset_sum/bit_unpacking/last_one_is_zero
        // column8_row82 * (column3_row0 - (column3_row1 + column3_row1))
        // TODO: figure out what Trace(8, 86) is
        let pedersen_hash0_ec_subset_sub_bit_unpacking_last_one_is_zero =
            (Expr::from(Trace(8, 86))
                * (Pedersen::Suffix.curr() - (Pedersen::Suffix.next() + Pedersen::Suffix.next())))
                / &every_256_row_zerofier;

        // pedersen/hash0/ec_subset_sum/bit_unpacking/zeroes_between_ones0
        // TODO: better name than shift
        let shift191 = Constant(FieldVariant::Fp(Fp::from(BigUint::from(2u32).pow(191u32))));
        let pedersen_hash0_ec_subset_sub_bit_unpacking_zeros_between_ones =
            (Expr::from(Trace(8, 86))
                * (Pedersen::Suffix.next() - Pedersen::Suffix.offset(192) * shift191))
                / &every_256_row_zerofier;

        // pedersen/hash0/ec_subset_sum/bit_unpacking/cumulative_bit192
        // TODO: column 4
        let pedersen_hash0_ec_subset_sum_bit_unpacking_cumulative_bit192 =
            (Expr::from(Trace(8, 86))
                - Expr::from(Trace(4, 255))
                    * (Pedersen::Suffix.offset(192)
                        - (Pedersen::Suffix.offset(193) + Pedersen::Suffix.offset(193))))
                / &every_256_row_zerofier;

        // pedersen/hash0/ec_subset_sum/bit_unpacking/zeroes_between_ones192
        let pedersen_hash0_ec_subset_sum_bit_unpacking_zeroes_between_ones192 =
            (Expr::from(Trace(4, 255)) * Pedersen::Suffix.offset(193)
                - Pedersen::Suffix.offset(196) * Constant(FieldVariant::Fp(Fp::from(8u32))))
                / &every_256_row_zerofier;

        // pedersen/hash0/ec_subset_sum/bit_unpacking/cumulative_bit196
        let pedersen_hash0_ec_subset_sum_bit_unpacking_cumulative_bit196 =
            (Expr::from(Trace(4, 255))
                - (Pedersen::Suffix.offset(251)
                    - (Pedersen::Suffix.offset(252) + Pedersen::Suffix.offset(252)))
                    * (Pedersen::Suffix.offset(196)
                        - (Pedersen::Suffix.offset(197) + Pedersen::Suffix.offset(197))))
                / &every_256_row_zerofier;

        // pedersen/hash0/ec_subset_sum/bit_unpacking/zeroes_between_ones196
        // (column3_row251 - (column3_row252 + column3_row252)) * (column3_row197 -
        // 18014398509481984 * column3_row251)
        let shift54 = Constant(FieldVariant::Fp(Fp::from(BigUint::from(2u32).pow(54u32))));
        let pedersen_hash0_ec_subset_sum_bit_unpacking_zeroes_between_ones196 = ((Pedersen::Suffix
            .offset(251)
            - (Pedersen::Suffix.offset(252) + Pedersen::Suffix.offset(252)))
            * (Pedersen::Suffix.offset(197) - Pedersen::Suffix.offset(251) * shift54))
            / &every_256_row_zerofier;

        // example for trace length n=512
        // =============================
        // X^(n/256) - ω^(255*n/256)    = (x-ω^255)(x-ω^511)
        // (x-ω^255)(x-ω^511) / (X^n-1) = 1/(x-ω^0)..(x-ω^254)(x-ω^256)..(x-ω^510)
        // vanishes on groups of 256 consecutive rows except the last row in each group
        // TODO: come up with better names for these
        let pedersen_transition_zerofier = (X.pow(n / 256)
            * Constant(FieldVariant::Fp(g.pow([(255 * n / 256) as u64]))))
            / &all_cycles_zerofier;

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
            * &pedersen_transition_zerofier;

        // example for trace length n=512
        // =============================
        // X^(n/256) - ω^(63*n/64)      = X^(n/256) - ω^(252*n/256)
        // X^(n/256) - ω^(255*n/256)    = (x-ω^252)(x-ω^508)
        // (x-ω^255)(x-ω^511) / (X^n-1) = 1/(x-ω^0)..(x-ω^254)(x-ω^256)..(x-ω^510)
        // vanishes on groups of 256 consecutive rows except the 252nd row of each group
        let pedersen_zero_suffix_zerofier =
            X.pow(n / 256) * Constant(FieldVariant::Fp(g.pow([(63 * n / 64) as u64])));

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
            Pedersen::Suffix.curr() / &pedersen_zero_suffix_zerofier;

        // TODO: is this constraint even needed?
        // check suffix in row 255 of each 256 row group is zero
        let pedersen_hash0_ec_subset_sum_zeros_tail = Pedersen::Suffix.curr()
            / (X.pow(n / 256) - Constant(FieldVariant::Fp(g.pow([255 * n as u64 / 256]))));

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
        // │   ω^252   │         0          │         0          │
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^253   │         0          │         0          │
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^254   │         0          │         0          │
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^255   │         0          │         0          │
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
        // │   ω^508   │         0          │         0          │
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^509   │         0          │         0          │
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^510   │         0          │         0          │
        // ├───────────┼────────────────────┼────────────────────┤
        // │   ω^511   │         0          │         0          │
        // └───────────┴────────────────────┴────────────────────┘
        let (pedersen_x_coeffs, pedersen_y_coeffs) = super::pedersen::constant_points_poly();
        let pedersen_points_x = Polynomial::new(pedersen_x_coeffs);
        let pedersen_points_y = Polynomial::new(pedersen_y_coeffs);

        // TODO: double check if the value that's being evaluated is correct
        let pedersen_point_y = pedersen_points_y.eval(X.pow(n / 512));
        let pedersen_point_x = pedersen_points_x.eval(X.pow(n / 512));

        // let `P = (Px, Py)` be the point to be added (see above)
        // let `Q = (Qx, Qy)` be the partial result
        // note that the slope = dy/dx with dy = Qy - Py, dx = Qx - Px
        // this constraint is equivalent to: bit * dy = dy/dx * dx
        // TODO: slope is 0 if bit is 0?
        let pedersen_hash0_ec_subset_sum_add_points_slope = (&pedersen_hash0_ec_subset_sum_b0
            * (Pedersen::PartialSumY.curr() - &pedersen_point_y)
            - Pedersen::Slope.curr() * (Pedersen::PartialSumX.curr() - &pedersen_point_x))
            * &pedersen_transition_zerofier;

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
            * &pedersen_transition_zerofier;
        let pedersen_hash0_ec_subset_sum_add_points_y = (&pedersen_hash0_ec_subset_sum_b0
            * (Pedersen::PartialSumY.curr() + Pedersen::PartialSumY.next())
            - Pedersen::Slope.curr()
                * (Pedersen::PartialSumX.curr() - Pedersen::PartialSumX.next()))
            * &pedersen_transition_zerofier;
        // if the bit is 0 then just copy the previous point
        let pedersen_hash0_ec_subset_sum_copy_point_x = (&pedersen_hash0_ec_subset_sum_b0_negate
            * (Pedersen::PartialSumX.next() - Pedersen::PartialSumX.curr()))
            * &pedersen_transition_zerofier;
        let pedersen_hash0_ec_subset_sum_copy_point_y = (&pedersen_hash0_ec_subset_sum_b0_negate
            * (Pedersen::PartialSumY.next() - Pedersen::PartialSumY.curr()))
            * &pedersen_transition_zerofier;

        // example for trace length n=1024
        // =============================
        // X^(n/512) - ω^(n/2)                = X^(n/512) - ω^(256*n/512)
        // X^(n/512) - ω^(256*n/512)          = (x-ω^256)(x-ω^768)
        // x^(n/256) - 1                      = (x-ω_0)(x-ω_256)(x-ω_512)(x-ω_768)
        // (x-ω^256)(x-ω^768) / (X^(n/256)-1) = 1/(x-ω_0)(x-ω_512)
        // 1/(X^(n/512) - 1)                  = 1/(x-ω_0)(x-ω_512)
        // NOTE: By using `(x-ω^256)(x-ω^768) / (X^(n/256)-1)` rather than
        // `1/(X^(n/512) - 1)` we save an inversion operation since 1 / (X^(n/256)-1)
        // has been calculated already and as a result of how constraints are
        // evaluated it will be cached.
        // TODO: check all zerofiers are being multiplied or divided correctly
        let every_512_row_zerofier = (X.pow(n / 512)
            - Constant(FieldVariant::Fp(g.pow([n as u64 / 2]))))
            / &every_256_row_zerofier;

        // A single pedersen hash `H(a, b)` is computed every 512 cycles.
        // The constraints for each hash is split in two consecutive 256 row groups.
        // - 1st group computes `e0 = P0 + a_low * P1 + a_high * P2`
        // - 2nd group computes `e1 = e0 + B_low * P3 + B_high * P4`
        // We make sure the initial value of each group is loaded correctly:
        // - 1st group we check P0 (the shift point) is the first partial sum
        // - 2nd group we check e0 (processed `a`) is the first partial sum
        let pedersen_hash0_copy_point_x = (Pedersen::PartialSumX.offset(256)
            - Pedersen::PartialSumX.offset(255))
            * &every_512_row_zerofier;
        let pedersen_hash0_copy_point_y = (Pedersen::PartialSumY.offset(256)
            - Pedersen::PartialSumY.offset(255))
            * &every_512_row_zerofier;
        // TODO: introducing a new zerofier that's equivalent to the
        // previous one? double check every_512_row_zerofier
        let every_512_row_zerofier = X.pow(n / 512) - Constant(FieldVariant::Fp(Fp::ONE));
        let shift_point = super::pedersen::params::PEDERSEN_SHIFT_POINT;
        let pedersen_hash0_init_x = (Pedersen::PartialSumX.curr()
            - Constant(FieldVariant::Fp(shift_point.x)))
            / &every_512_row_zerofier;
        let pedersen_hash0_init_y = (Pedersen::PartialSumY.curr()
            - Constant(FieldVariant::Fp(shift_point.y)))
            / &every_512_row_zerofier;

        // TODO: fix naming
        let zerofier_512th_last_row =
            X - Constant(FieldVariant::Fp(g.pow([512 * (n as u64 / 512 - 1)])));
        let every_512_rows_except_last_zerofier =
            &zerofier_512th_last_row / &every_512_row_zerofier;

        // Link Input0 into the memory pool.
        let pedersen_input0_value0 =
            (Npc::PedersenInput0Val.curr() - Pedersen::Suffix.curr()) / &every_512_row_zerofier;
        // Input0's next address should be the address directly
        // after the output address of the previous hash
        let pedersen_input0_addr = (Npc::PedersenInput0Addr.next()
            - (Npc::PedersenOutputAddr.curr() + &one))
            * &every_512_rows_except_last_zerofier;
        // Ensure the first pedersen address matches the hint
        let pedersen_init_addr = (Npc::PedersenInput0Addr.curr()
            - PublicInputHint::InitialPedersenAddr.hint())
            / &first_row_zerofier;

        // Link Input1 into the memory pool.
        // Input1's address should be the address directly after input0's address
        let pedersen_input1_value0 = (Npc::PedersenInput1Val.curr() - Pedersen::Suffix.offset(256))
            / &every_512_row_zerofier;
        let pedersen_input1_addr = (Npc::PedersenInput1Addr.curr()
            - (Npc::PedersenInput0Addr.curr() + &one))
            / &every_512_row_zerofier;

        // Link pedersen output into the memory pool.
        // Output's address should be the address directly after input1's address.
        let pedersen_output_value0 = (Npc::PedersenOutputVal.curr()
            - Pedersen::PartialSumX.offset(511))
            / &every_512_row_zerofier;
        let pedersen_output_addr = (Npc::PedersenOutputAddr.curr()
            - (Npc::PedersenInput1Addr.curr() + &one))
            / &every_512_row_zerofier;

        // 128bit Range check builtin
        // ===================

        // TODO: fix naming
        let zerofier_256th_last_row =
            X - Constant(FieldVariant::Fp(g.pow([256 * (n as u64 / 256 - 1)])));
        let every_256_rows_except_last_zerofier =
            &zerofier_256th_last_row / &every_256_row_zerofier;

        // Hook up range check with the memory pool
        let rc_builtin_value =
            (rc_builtin_value7_0 - Npc::RangeCheck128Val.curr()) / &every_256_row_zerofier;
        let rc_builtin_addr_step = (Npc::RangeCheck128Addr.next()
            - (Npc::RangeCheck128Addr.curr() + &one))
            * &every_256_rows_except_last_zerofier;

        let rc_builtin_init_addr = (Npc::RangeCheck128Addr.curr()
            - PublicInputHint::InitialRcAddr.hint())
            / &first_row_zerofier;

        // X^(n/512) - ω^(n/2)    = (x-ω^255)(x-ω^511)
        // (x-ω^255)(x-ω^511) / (X^n-1) = 1/(x-ω^0)..(x-ω^254)(x-ω^256)..(x-ω^510)
        // vanishes on groups of 256 consecutive rows except the last row in each group

        // point^(trace_length / 512) - trace_generator^(trace_length / 2).
        // let pedersen_hash0_copy_point_x =

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
            // TODO: diluted constraints
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
        ]
        .into_iter()
        .map(Constraint::new)
        .collect()
    }

    fn gen_hints(
        trace_len: usize,
        execution_info: &ExecutionInfo<Self::Fp>,
        challenges: &Challenges<Self::Fq>,
    ) -> Hints<Self::Fq> {
        use PublicInputHint::*;
        let ExecutionInfo {
            initial_ap,
            initial_pc,
            final_ap,
            final_pc,
            range_check_min,
            range_check_max,
            public_memory,
            public_memory_padding_address,
            public_memory_padding_value,
        } = execution_info;

        let memory_product = utils::compute_public_memory_quotient(
            challenges[MemoryPermutation::Z],
            challenges[MemoryPermutation::A],
            trace_len,
            public_memory,
            (*public_memory_padding_address as u64).into(),
            *public_memory_padding_value,
        );

        assert!(range_check_min <= range_check_max);
        assert!(*range_check_max < 2usize.pow(16));

        Hints::new(vec![
            (InitialAp.index(), *initial_ap),
            (InitialPc.index(), *initial_pc),
            (FinalAp.index(), *final_ap),
            (FinalPc.index(), *final_pc),
            // TODO: this is a wrong value. Must fix
            (MemoryProduct.index(), memory_product),
            (RangeCheckProduct.index(), Fp::ONE),
            (RangeCheckMin.index(), (*range_check_min as u64).into()),
            (RangeCheckMax.index(), (*range_check_max as u64).into()),
            // TODO: Use proper initial
            (InitialPedersenAddr.index(), Fp::ONE),
            // TODO: Use proper initial
            (InitialRcAddr.index(), Fp::ONE),
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
pub enum Pedersen {
    PartialSumX,
    PartialSumY,
    Suffix,
    Slope,
}

impl ExecutionTraceColumn for Pedersen {
    fn index(&self) -> usize {
        match self {
            Self::PartialSumX => 1,
            Self::PartialSumY => 2,
            Self::Suffix => 3,
            Self::Slope => 4,
        }
    }

    fn offset<T>(&self, offset: isize) -> Expr<AlgebraicItem<T>> {
        let column = self.index();
        let trace_offset = match self {
            Self::PartialSumX | Self::PartialSumY | Self::Suffix | Self::Slope => offset,
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

    MemDstAddr = 8,
    MemDst = 9,
    // NOTE: cycle cells 10 and 11 is occupied by PubMemAddr since the public memory step is 8.
    // This means it applies twice (2, 3) then (8+2, 8+3) within a single 16 row cycle.
    MemOp1Addr = 12,
    MemOp1 = 13,
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
            Self::Pc
            | Self::Instruction
            | Self::MemOp0Addr
            | Self::MemOp0
            | Self::MemDstAddr
            | Self::MemDst
            | Self::MemOp1Addr
            | Self::MemOp1 => CYCLE_HEIGHT,
        } as isize;
        let column = self.index();
        let trace_offset = step * offset + *self as isize;
        AlgebraicItem::Trace(column, trace_offset).into()
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

// Trace column 7
#[derive(Clone, Copy)]
pub enum RangeCheck {
    OffDst = 0,
    Ordered = 2, // Stores ordered values for the range check
    Ap = 3,      // Allocation pointer (ap)
    // TODO 2
    OffOp1 = 4,
    // Ordered = 6 - trace step is 4
    Op0MulOp1 = 7, // =op0*op1
    OffOp0 = 8,
    // Ordered = 10 - trace step is 4
    Fp = 11, // Frame pointer (fp)
    // This cell alternates cycle to cycle between:
    // - Being used for the 128 bit range checks builtin - even cycles
    // - Filled with padding to fill any gaps - odd cycles
    Unused = 12,
    // Ordered = 14 - trace step is 4
    Res = 15,
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
    Tmp0 = 0,
    Tmp1 = 8,
}

impl ExecutionTraceColumn for Auxiliary {
    fn index(&self) -> usize {
        8
    }

    fn offset<T>(&self, cycle_offset: isize) -> Expr<AlgebraicItem<T>> {
        let column = self.index();
        let trace_offset = CYCLE_HEIGHT as isize * cycle_offset + *self as isize;
        AlgebraicItem::Trace(column, trace_offset).into()
    }
}

// Trace column 6 - permutations
#[derive(Clone, Copy)]
pub enum Permutation {
    // TODO = 0,
    Memory = 0,
    RangeCheck = 1,
}

impl ExecutionTraceColumn for Permutation {
    fn index(&self) -> usize {
        9
    }

    fn offset<T>(&self, offset: isize) -> Expr<AlgebraicItem<T>> {
        let column = self.index();
        let trace_offset = match self {
            Permutation::Memory => MEMORY_STEP as isize * offset + *self as isize,
            Permutation::RangeCheck => 4 * offset + *self as isize,
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
    MemoryProduct, // TODO
    RangeCheckProduct,
    RangeCheckMin,
    RangeCheckMax,
    InitialPedersenAddr,
    InitialRcAddr,
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

struct Polynomial<T>(Vec<T>);

impl<T: Clone + Zero + Mul<Output = T> + Add<Output = T>> Polynomial<T> {
    fn new(coeffs: Vec<T>) -> Self {
        assert!(!coeffs.is_empty());
        assert!(!coeffs.iter().all(|v| v.is_zero()));
        Polynomial(coeffs)
    }

    fn eval(&self, x: Expr<AlgebraicItem<T>>) -> Expr<AlgebraicItem<T>> {
        let mut res = Expr::Leaf(AlgebraicItem::Constant(T::zero()));
        let mut acc = x;
        for coeff in &self.0 {
            res += &acc * AlgebraicItem::Constant(coeff.clone());
            acc *= acc.clone();
        }
        res
    }
}
