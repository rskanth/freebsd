//===-- MSP430ISelDAGToDAG.cpp - A dag to dag inst selector for MSP430 ----===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines an instruction selector for the MSP430 target.
//
//===----------------------------------------------------------------------===//

#include "MSP430.h"
#include "MSP430TargetMachine.h"
#include "llvm/DerivedTypes.h"
#include "llvm/Function.h"
#include "llvm/Intrinsics.h"
#include "llvm/CallingConv.h"
#include "llvm/Constants.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/SelectionDAG.h"
#include "llvm/CodeGen/SelectionDAGISel.h"
#include "llvm/Target/TargetLowering.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"
using namespace llvm;

namespace {
  struct MSP430ISelAddressMode {
    enum {
      RegBase,
      FrameIndexBase
    } BaseType;

    struct {            // This is really a union, discriminated by BaseType!
      SDValue Reg;
      int FrameIndex;
    } Base;

    int16_t Disp;
    const GlobalValue *GV;
    const Constant *CP;
    const BlockAddress *BlockAddr;
    const char *ES;
    int JT;
    unsigned Align;    // CP alignment.

    MSP430ISelAddressMode()
      : BaseType(RegBase), Disp(0), GV(0), CP(0), BlockAddr(0),
        ES(0), JT(-1), Align(0) {
    }

    bool hasSymbolicDisplacement() const {
      return GV != 0 || CP != 0 || ES != 0 || JT != -1;
    }

    bool hasBaseReg() const {
      return Base.Reg.getNode() != 0;
    }

    void setBaseReg(SDValue Reg) {
      BaseType = RegBase;
      Base.Reg = Reg;
    }

    void dump() {
      errs() << "MSP430ISelAddressMode " << this << '\n';
      if (BaseType == RegBase && Base.Reg.getNode() != 0) {
        errs() << "Base.Reg ";
        Base.Reg.getNode()->dump();
      } else if (BaseType == FrameIndexBase) {
        errs() << " Base.FrameIndex " << Base.FrameIndex << '\n';
      }
      errs() << " Disp " << Disp << '\n';
      if (GV) {
        errs() << "GV ";
        GV->dump();
      } else if (CP) {
        errs() << " CP ";
        CP->dump();
        errs() << " Align" << Align << '\n';
      } else if (ES) {
        errs() << "ES ";
        errs() << ES << '\n';
      } else if (JT != -1)
        errs() << " JT" << JT << " Align" << Align << '\n';
    }
  };
}

/// MSP430DAGToDAGISel - MSP430 specific code to select MSP430 machine
/// instructions for SelectionDAG operations.
///
namespace {
  class MSP430DAGToDAGISel : public SelectionDAGISel {
    const MSP430TargetLowering &Lowering;
    const MSP430Subtarget &Subtarget;

  public:
    MSP430DAGToDAGISel(MSP430TargetMachine &TM, CodeGenOpt::Level OptLevel)
      : SelectionDAGISel(TM, OptLevel),
        Lowering(*TM.getTargetLowering()),
        Subtarget(*TM.getSubtargetImpl()) { }

    virtual const char *getPassName() const {
      return "MSP430 DAG->DAG Pattern Instruction Selection";
    }

    bool MatchAddress(SDValue N, MSP430ISelAddressMode &AM);
    bool MatchWrapper(SDValue N, MSP430ISelAddressMode &AM);
    bool MatchAddressBase(SDValue N, MSP430ISelAddressMode &AM);

    virtual bool
    SelectInlineAsmMemoryOperand(const SDValue &Op, char ConstraintCode,
                                 std::vector<SDValue> &OutOps);

    // Include the pieces autogenerated from the target description.
  #include "MSP430GenDAGISel.inc"

  private:
    SDNode *Select(SDNode *N);
    SDNode *SelectIndexedLoad(SDNode *Op);
    SDNode *SelectIndexedBinOp(SDNode *Op, SDValue N1, SDValue N2,
                               unsigned Opc8, unsigned Opc16);

    bool SelectAddr(SDNode *Op, SDValue Addr, SDValue &Base, SDValue &Disp);
  };
}  // end anonymous namespace

/// createMSP430ISelDag - This pass converts a legalized DAG into a
/// MSP430-specific DAG, ready for instruction scheduling.
///
FunctionPass *llvm::createMSP430ISelDag(MSP430TargetMachine &TM,
                                        CodeGenOpt::Level OptLevel) {
  return new MSP430DAGToDAGISel(TM, OptLevel);
}


/// MatchWrapper - Try to match MSP430ISD::Wrapper node into an addressing mode.
/// These wrap things that will resolve down into a symbol reference.  If no
/// match is possible, this returns true, otherwise it returns false.
bool MSP430DAGToDAGISel::MatchWrapper(SDValue N, MSP430ISelAddressMode &AM) {
  // If the addressing mode already has a symbol as the displacement, we can
  // never match another symbol.
  if (AM.hasSymbolicDisplacement())
    return true;

  SDValue N0 = N.getOperand(0);

  if (GlobalAddressSDNode *G = dyn_cast<GlobalAddressSDNode>(N0)) {
    AM.GV = G->getGlobal();
    AM.Disp += G->getOffset();
    //AM.SymbolFlags = G->getTargetFlags();
  } else if (ConstantPoolSDNode *CP = dyn_cast<ConstantPoolSDNode>(N0)) {
    AM.CP = CP->getConstVal();
    AM.Align = CP->getAlignment();
    AM.Disp += CP->getOffset();
    //AM.SymbolFlags = CP->getTargetFlags();
  } else if (ExternalSymbolSDNode *S = dyn_cast<ExternalSymbolSDNode>(N0)) {
    AM.ES = S->getSymbol();
    //AM.SymbolFlags = S->getTargetFlags();
  } else if (JumpTableSDNode *J = dyn_cast<JumpTableSDNode>(N0)) {
    AM.JT = J->getIndex();
    //AM.SymbolFlags = J->getTargetFlags();
  } else {
    AM.BlockAddr = cast<BlockAddressSDNode>(N0)->getBlockAddress();
    //AM.SymbolFlags = cast<BlockAddressSDNode>(N0)->getTargetFlags();
  }
  return false;
}

/// MatchAddressBase - Helper for MatchAddress. Add the specified node to the
/// specified addressing mode without any further recursion.
bool MSP430DAGToDAGISel::MatchAddressBase(SDValue N, MSP430ISelAddressMode &AM) {
  // Is the base register already occupied?
  if (AM.BaseType != MSP430ISelAddressMode::RegBase || AM.Base.Reg.getNode()) {
    // If so, we cannot select it.
    return true;
  }

  // Default, generate it as a register.
  AM.BaseType = MSP430ISelAddressMode::RegBase;
  AM.Base.Reg = N;
  return false;
}

bool MSP430DAGToDAGISel::MatchAddress(SDValue N, MSP430ISelAddressMode &AM) {
  DEBUG(errs() << "MatchAddress: "; AM.dump());

  switch (N.getOpcode()) {
  default: break;
  case ISD::Constant: {
    uint64_t Val = cast<ConstantSDNode>(N)->getSExtValue();
    AM.Disp += Val;
    return false;
  }

  case MSP430ISD::Wrapper:
    if (!MatchWrapper(N, AM))
      return false;
    break;

  case ISD::FrameIndex:
    if (AM.BaseType == MSP430ISelAddressMode::RegBase
        && AM.Base.Reg.getNode() == 0) {
      AM.BaseType = MSP430ISelAddressMode::FrameIndexBase;
      AM.Base.FrameIndex = cast<FrameIndexSDNode>(N)->getIndex();
      return false;
    }
    break;

  case ISD::ADD: {
    MSP430ISelAddressMode Backup = AM;
    if (!MatchAddress(N.getNode()->getOperand(0), AM) &&
        !MatchAddress(N.getNode()->getOperand(1), AM))
      return false;
    AM = Backup;
    if (!MatchAddress(N.getNode()->getOperand(1), AM) &&
        !MatchAddress(N.getNode()->getOperand(0), AM))
      return false;
    AM = Backup;

    break;
  }

  case ISD::OR:
    // Handle "X | C" as "X + C" iff X is known to have C bits clear.
    if (ConstantSDNode *CN = dyn_cast<ConstantSDNode>(N.getOperand(1))) {
      MSP430ISelAddressMode Backup = AM;
      uint64_t Offset = CN->getSExtValue();
      // Start with the LHS as an addr mode.
      if (!MatchAddress(N.getOperand(0), AM) &&
          // Address could not have picked a GV address for the displacement.
          AM.GV == NULL &&
          // Check to see if the LHS & C is zero.
          CurDAG->MaskedValueIsZero(N.getOperand(0), CN->getAPIntValue())) {
        AM.Disp += Offset;
        return false;
      }
      AM = Backup;
    }
    break;
  }

  return MatchAddressBase(N, AM);
}

/// SelectAddr - returns true if it is able pattern match an addressing mode.
/// It returns the operands which make up the maximal addressing mode it can
/// match by reference.
bool MSP430DAGToDAGISel::SelectAddr(SDNode *Op, SDValue N,
                                    SDValue &Base, SDValue &Disp) {
  MSP430ISelAddressMode AM;

  if (MatchAddress(N, AM))
    return false;

  EVT VT = N.getValueType();
  if (AM.BaseType == MSP430ISelAddressMode::RegBase) {
    if (!AM.Base.Reg.getNode())
      AM.Base.Reg = CurDAG->getRegister(0, VT);
  }

  Base  = (AM.BaseType == MSP430ISelAddressMode::FrameIndexBase) ?
    CurDAG->getTargetFrameIndex(AM.Base.FrameIndex, TLI.getPointerTy()) :
    AM.Base.Reg;

  if (AM.GV)
    Disp = CurDAG->getTargetGlobalAddress(AM.GV, MVT::i16, AM.Disp,
                                          0/*AM.SymbolFlags*/);
  else if (AM.CP)
    Disp = CurDAG->getTargetConstantPool(AM.CP, MVT::i16,
                                         AM.Align, AM.Disp, 0/*AM.SymbolFlags*/);
  else if (AM.ES)
    Disp = CurDAG->getTargetExternalSymbol(AM.ES, MVT::i16, 0/*AM.SymbolFlags*/);
  else if (AM.JT != -1)
    Disp = CurDAG->getTargetJumpTable(AM.JT, MVT::i16, 0/*AM.SymbolFlags*/);
  else if (AM.BlockAddr)
    Disp = CurDAG->getBlockAddress(AM.BlockAddr, MVT::i32,
                                   true, 0/*AM.SymbolFlags*/);
  else
    Disp = CurDAG->getTargetConstant(AM.Disp, MVT::i16);

  return true;
}

bool MSP430DAGToDAGISel::
SelectInlineAsmMemoryOperand(const SDValue &Op, char ConstraintCode,
                             std::vector<SDValue> &OutOps) {
  SDValue Op0, Op1;
  switch (ConstraintCode) {
  default: return true;
  case 'm':   // memory
    if (!SelectAddr(Op.getNode(), Op, Op0, Op1))
      return true;
    break;
  }

  OutOps.push_back(Op0);
  OutOps.push_back(Op1);
  return false;
}

static bool isValidIndexedLoad(const LoadSDNode *LD) {
  ISD::MemIndexedMode AM = LD->getAddressingMode();
  if (AM != ISD::POST_INC || LD->getExtensionType() != ISD::NON_EXTLOAD)
    return false;

  EVT VT = LD->getMemoryVT();

  switch (VT.getSimpleVT().SimpleTy) {
  case MVT::i8:
    // Sanity check
    if (cast<ConstantSDNode>(LD->getOffset())->getZExtValue() != 1)
      return false;

    break;
  case MVT::i16:
    // Sanity check
    if (cast<ConstantSDNode>(LD->getOffset())->getZExtValue() != 2)
      return false;

    break;
  default:
    return false;
  }

  return true;
}

SDNode *MSP430DAGToDAGISel::SelectIndexedLoad(SDNode *N) {
  LoadSDNode *LD = cast<LoadSDNode>(N);
  if (!isValidIndexedLoad(LD))
    return NULL;

  MVT VT = LD->getMemoryVT().getSimpleVT();

  unsigned Opcode = 0;
  switch (VT.SimpleTy) {
  case MVT::i8:
    Opcode = MSP430::MOV8rm_POST;
    break;
  case MVT::i16:
    Opcode = MSP430::MOV16rm_POST;
    break;
  default:
    return NULL;
  }

   return CurDAG->getMachineNode(Opcode, N->getDebugLoc(),
                                 VT, MVT::i16, MVT::Other,
                                 LD->getBasePtr(), LD->getChain());
}

SDNode *MSP430DAGToDAGISel::SelectIndexedBinOp(SDNode *Op,
                                               SDValue N1, SDValue N2,
                                               unsigned Opc8, unsigned Opc16) {
  if (N1.getOpcode() == ISD::LOAD &&
      N1.hasOneUse() &&
      IsLegalToFold(N1, Op, Op, OptLevel)) {
    LoadSDNode *LD = cast<LoadSDNode>(N1);
    if (!isValidIndexedLoad(LD))
      return NULL;

    MVT VT = LD->getMemoryVT().getSimpleVT();
    unsigned Opc = (VT == MVT::i16 ? Opc16 : Opc8);
    MachineSDNode::mmo_iterator MemRefs0 = MF->allocateMemRefsArray(1);
    MemRefs0[0] = cast<MemSDNode>(N1)->getMemOperand();
    SDValue Ops0[] = { N2, LD->getBasePtr(), LD->getChain() };
    SDNode *ResNode =
      CurDAG->SelectNodeTo(Op, Opc,
                           VT, MVT::i16, MVT::Other,
                           Ops0, 3);
    cast<MachineSDNode>(ResNode)->setMemRefs(MemRefs0, MemRefs0 + 1);
    // Transfer chain.
    ReplaceUses(SDValue(N1.getNode(), 2), SDValue(ResNode, 2));
    // Transfer writeback.
    ReplaceUses(SDValue(N1.getNode(), 1), SDValue(ResNode, 1));
    return ResNode;
  }

  return NULL;
}


SDNode *MSP430DAGToDAGISel::Select(SDNode *Node) {
  DebugLoc dl = Node->getDebugLoc();

  // Dump information about the Node being selected
  DEBUG(errs() << "Selecting: ");
  DEBUG(Node->dump(CurDAG));
  DEBUG(errs() << "\n");

  // If we have a custom node, we already have selected!
  if (Node->isMachineOpcode()) {
    DEBUG(errs() << "== ";
          Node->dump(CurDAG);
          errs() << "\n");
    return NULL;
  }

  // Few custom selection stuff.
  switch (Node->getOpcode()) {
  default: break;
  case ISD::FrameIndex: {
    assert(Node->getValueType(0) == MVT::i16);
    int FI = cast<FrameIndexSDNode>(Node)->getIndex();
    SDValue TFI = CurDAG->getTargetFrameIndex(FI, MVT::i16);
    if (Node->hasOneUse())
      return CurDAG->SelectNodeTo(Node, MSP430::ADD16ri, MVT::i16,
                                  TFI, CurDAG->getTargetConstant(0, MVT::i16));
    return CurDAG->getMachineNode(MSP430::ADD16ri, dl, MVT::i16,
                                  TFI, CurDAG->getTargetConstant(0, MVT::i16));
  }
  case ISD::LOAD:
    if (SDNode *ResNode = SelectIndexedLoad(Node))
      return ResNode;
    // Other cases are autogenerated.
    break;
  case ISD::ADD:
    if (SDNode *ResNode =
        SelectIndexedBinOp(Node,
                           Node->getOperand(0), Node->getOperand(1),
                           MSP430::ADD8rm_POST, MSP430::ADD16rm_POST))
      return ResNode;
    else if (SDNode *ResNode =
             SelectIndexedBinOp(Node, Node->getOperand(1), Node->getOperand(0),
                                MSP430::ADD8rm_POST, MSP430::ADD16rm_POST))
      return ResNode;

    // Other cases are autogenerated.
    break;
  case ISD::SUB:
    if (SDNode *ResNode =
        SelectIndexedBinOp(Node,
                           Node->getOperand(0), Node->getOperand(1),
                           MSP430::SUB8rm_POST, MSP430::SUB16rm_POST))
      return ResNode;

    // Other cases are autogenerated.
    break;
  case ISD::AND:
    if (SDNode *ResNode =
        SelectIndexedBinOp(Node,
                           Node->getOperand(0), Node->getOperand(1),
                           MSP430::AND8rm_POST, MSP430::AND16rm_POST))
      return ResNode;
    else if (SDNode *ResNode =
             SelectIndexedBinOp(Node, Node->getOperand(1), Node->getOperand(0),
                                MSP430::AND8rm_POST, MSP430::AND16rm_POST))
      return ResNode;

    // Other cases are autogenerated.
    break;
  case ISD::OR:
    if (SDNode *ResNode =
        SelectIndexedBinOp(Node,
                           Node->getOperand(0), Node->getOperand(1),
                           MSP430::OR8rm_POST, MSP430::OR16rm_POST))
      return ResNode;
    else if (SDNode *ResNode =
             SelectIndexedBinOp(Node, Node->getOperand(1), Node->getOperand(0),
                                MSP430::OR8rm_POST, MSP430::OR16rm_POST))
      return ResNode;

    // Other cases are autogenerated.
    break;
  case ISD::XOR:
    if (SDNode *ResNode =
        SelectIndexedBinOp(Node,
                           Node->getOperand(0), Node->getOperand(1),
                           MSP430::XOR8rm_POST, MSP430::XOR16rm_POST))
      return ResNode;
    else if (SDNode *ResNode =
             SelectIndexedBinOp(Node, Node->getOperand(1), Node->getOperand(0),
                                MSP430::XOR8rm_POST, MSP430::XOR16rm_POST))
      return ResNode;

    // Other cases are autogenerated.
    break;
  }

  // Select the default instruction
  SDNode *ResNode = SelectCode(Node);

  DEBUG(errs() << "=> ");
  if (ResNode == NULL || ResNode == Node)
    DEBUG(Node->dump(CurDAG));
  else
    DEBUG(ResNode->dump(CurDAG));
  DEBUG(errs() << "\n");

  return ResNode;
}
