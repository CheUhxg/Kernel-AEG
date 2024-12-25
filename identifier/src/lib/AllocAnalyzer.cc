/*
 * Copyright (C) 2019 Yueqi (Lewis) Chen, Zhenpeng Lin
 *
 * For licensing details see LICENSE
 */

#include <llvm/IR/TypeFinder.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/Pass.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Function.h>
#include <llvm/Support/Debug.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Constants.h>
#include <llvm/ADT/StringExtras.h>
#include <llvm/Analysis/CallGraph.h>

#include "AllocAnalyzer.h"
#include "Annotation.h"
#include "Common.h"
#include "GlobalCtx.h"
#include "StructAnalyzer.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Value.h"
#include "llvm/Support/Casting.h"

using namespace llvm;
using namespace std;

extern cl::opt<bool> IgnoreReachable;

// initialize moduleStructMap
bool AllocAnalyzerPass::doInitialization(Module* M) {

    StructTypeSet structTypeSet;
    TypeFinder usedStructTypes;
    usedStructTypes.run(*M, false);

    for (TypeFinder::iterator itr = usedStructTypes.begin(), 
            ite = usedStructTypes.end(); itr != ite; itr++) {

        StructType* st = *itr;
        // only deal with non-opaque type
        if (st->isOpaque()) 
            continue;

        structTypeSet.insert(st);
    }

    Ctx->moduleStructMap.insert(std::make_pair(M, structTypeSet));

    if(Ctx->LeakAPIs.size() == 0){
        composeMbufLeakAPI();
    }

    return false;
}

// determine "allocable" and "leakable" to compute allocInstMap and copyInstMap
bool AllocAnalyzerPass::doModulePass(Module* M) {

    ModuleStructMap::iterator it = Ctx->moduleStructMap.find(M);
    assert(it != Ctx->moduleStructMap.end() && 
            "M is not analyzed in doInitialization");

    // no flexible structure usage in this module
    // TODO Lewis: is this a golden rule?
    // Counter example: leak in M1, struct info in M2 and pass to M1
    if (it->second.size() == 0)
        return false;

	for (Function &F : *M)
        runOnFunction(&F);

    return false;
}

// check if the function is called by a priviledged device
// return true if the function is priviledged.
bool AllocAnalyzerPass::isPriviledged(llvm::Function *F) {
    return false;
    SmallVector<Function*, 4> workList;
    workList.clear();
    workList.push_back(F);

    FuncSet seen;
    seen.clear();

    while (!workList.empty()) {
        Function* F = workList.pop_back_val();

        // check if the function lies in the deny list
        if (Ctx->devDenyList.find(F) != Ctx->devDenyList.end()) {
            return true;
        }

        if (!seen.insert(F).second)
            continue;

        CallerMap::iterator it = Ctx->Callers.find(F);
        if (it != Ctx->Callers.end()) {
            for (auto calleeInst: it->second) {
                Function* F = calleeInst->getParent()->getParent();
                workList.push_back(F);
            }
        }
    }
    return false;
}


// start analysis from calling to allocation or leak functions
void AllocAnalyzerPass::runOnFunction(Function *F) {
    if(!IgnoreReachable){
        FuncSet Syscalls = reachableSyscall(F);
        if(Syscalls.size() == 0){
            return;
        }
        KA_LOGS(1, F->getName() << " can be reached by " << Syscalls.size() << " syscalls\n");
    }

    // skip functions in .init.text which is used only during booting
    if(F->hasSection() && F->getSection().str() == ".init.text")
        return;

    if (F->getName().equals("selinux_xfrm_alloc_user")) {
        KA_LOGS(0, "[GOOD]\n");
    }
    for (inst_iterator i = inst_begin(F), e = inst_end(F); i != e; i++) {
        Instruction* I = &*i;
        if (CallInst *callInst = dyn_cast<CallInst>(I)) {
            const Function* callee = callInst->getCalledFunction();
            if (!callee)
                callee = dyn_cast<Function>(callInst->getCalledOperand()->stripPointerCasts());
            if (callee) {
                std::string calleeName = callee->getName().str();
                if (isCall2Alloc(calleeName)) {
                    analyzeAlloc(callInst); // flexible part
                }
            }
        }
    }

    return;
}

bool AllocAnalyzerPass::isCall2Alloc(std::string calleeName) {
    if (std::find(allocAPIVec.begin(), allocAPIVec.end(), 
            calleeName) != allocAPIVec.end())
        return true;
    // else if(calleeName.find("alloc") != std::string::npos
    //          || calleeName.find("ALLOC") != std::string::npos)
    //     // aggressive analysis
    //     return true;
    return false;
}

void AllocAnalyzerPass::backwardUseAnalysis(llvm::Value *V, std::set<llvm::Value *> &DefineSet){
    // TODO: handle reg2mem store load pair
    if(auto *I = dyn_cast<Instruction>(V)){
        KA_LOGS(2, "backward handling " << *I << "\n");
        if(I->isBinaryOp() || dyn_cast<ICmpInst>(I)){
            KA_LOGS(2, *I << " backward Adding " << *V << "\n");
            DefineSet.insert(V);

            for (unsigned i = 0, e = I->getNumOperands(); i != e; i++) {
                Value* Opd = I->getOperand(i);
                KA_LOGS(2, "backward Adding " << *V << "\n");
                DefineSet.insert(V);
                if (dyn_cast<ConstantInt>(Opd))
                    continue;
                backwardUseAnalysis(Opd, DefineSet);
            }

        } else if(dyn_cast<CallInst>(I) ||
                      dyn_cast<SelectInst>(I)){
            KA_LOGS(2, "backward Adding " << *V << "\n");
            DefineSet.insert(V);
        } else if(auto *PN = dyn_cast<PHINode>(I)){

            if(DefineSet.find(V) != DefineSet.end())
                return;

            KA_LOGS(2, "backward Adding " << *V << "\n");
            DefineSet.insert(V);
            // aggressive analysis
            for (unsigned i = 0, e = PN->getNumIncomingValues(); i != e; i++) {
                Value* IV = PN->getIncomingValue(i);
                if (dyn_cast<ConstantInt>(IV))
                    continue;
                backwardUseAnalysis(IV, DefineSet);
            }

        }else if(UnaryInstruction* UI = dyn_cast<UnaryInstruction>(V)){
            KA_LOGS(2, "backward Adding " << *V << "\n");
            DefineSet.insert(V);

            backwardUseAnalysis(UI->getOperand(0), DefineSet);
        }else if(auto *GEP = dyn_cast<GetElementPtrInst>(I)){
            // may come from the same struct
            KA_LOGS(2, "backward Adding " << *V << "\n");
            DefineSet.insert(V);

            backwardUseAnalysis(GEP->getOperand(0), DefineSet);
        }else{
            errs() << "Backward Fatal errors , please handle " << *I << "\n";
            // exit(0);
        }
    }else{
        // argument
        KA_LOGS(2, "Backward Adding " << *V << "\n");
        DefineSet.insert(V);
    }
}

llvm::Value* AllocAnalyzerPass::getOffset(llvm::GetElementPtrInst *GEP){
    // FIXME: consider using more sophisicated method
    // Use the last indice of GEP
    return GEP->getOperand(GEP->getNumIndices());
}


void AllocAnalyzerPass::forwardAnalysis(llvm::Value *V, 
                                        std::set<llvm::StoreInst *> &StoreInstSet,
                                        std::set<llvm::Value *> &TrackSet){


    for (auto *User : V->users()){

        if(TrackSet.find(User) != TrackSet.end())
            continue;

        TrackSet.insert(User);

        KA_LOGS(2, "Forward " << *User << "\n");

        // FIXME: should we check if V is SI's pointer?
        if(StoreInst *SI = dyn_cast<StoreInst>(User)){
            StoreInstSet.insert(SI);

            // forward memory alias
            Value *SV = SI->getValueOperand();
            Value *SP = SI->getPointerOperand();

            for(auto *StoreU : SP->users()){
                // alias pair
                if(dyn_cast<LoadInst>(StoreU)){
                    KA_LOGS(2, "Found Store and Load pair " << *StoreU << " " << *User << "\n");
                    forwardAnalysis(StoreU, StoreInstSet, TrackSet);
                }
            }

            // handle struct alias
            if(auto *GEP = dyn_cast<GetElementPtrInst>(SP)){
                Value *red_offset = getOffset(GEP);
                Value *red_obj = GEP->getOperand(0);
                
                KA_LOGS(2, "Marking " << *red_obj << " as red\n");

                for(auto *ObjU : red_obj->users()){
                    if(auto *ObjGEP = dyn_cast<GetElementPtrInst>(ObjU)){

                        if(ObjGEP != GEP && getOffset(ObjGEP) == red_offset){
                            // we found it
                            // and then check if its user is LOAD.
                            for(auto *OGEPUser : ObjGEP->users()){
                                if(dyn_cast<LoadInst>(OGEPUser)){
                                    KA_LOGS(2, "Solved Alias : " << *OGEPUser << " == " << *User << "\n");
                                    forwardAnalysis(OGEPUser, StoreInstSet, TrackSet);
                                }
                            }
                        }
                    }
                }
                // should we forward sturct ?

            }
        } else if(dyn_cast<GetElementPtrInst>(User) ||
                    dyn_cast<ICmpInst>(User) ||
                        dyn_cast<BranchInst>(User) ||
                    dyn_cast<BinaryOperator>(User)){

            forwardAnalysis(User, StoreInstSet, TrackSet);

        } else if(dyn_cast<CallInst>(User) ||
                    dyn_cast<CallBrInst>(User) ||
                    dyn_cast<SwitchInst>(User) ||
                        dyn_cast<ReturnInst>(User)){

                continue;

        // } else if(dyn_cast<UnaryInstruction>(User)){
        } else if(dyn_cast<SExtInst>(User) || dyn_cast<ZExtInst>(User)
                    || dyn_cast<TruncInst>(User)){

            forwardAnalysis(User, StoreInstSet, TrackSet);

        } else if(dyn_cast<PHINode>(User) || 
                    dyn_cast<SelectInst>(User) ||
                        dyn_cast<LoadInst>(User) ||
                    dyn_cast<UnaryInstruction>(User)){
                            
            // TODO: forward PHI node
            forwardAnalysis(User, StoreInstSet, TrackSet);

        } else {
            errs() << "\nForwardAnalysis Fatal errors , please handle " << *User << "\n";
            // exit(0);
        }
    }
}


// customize flexible part here
// every time adding a new struct to allocInstMap, 
// update allocSyscallMap
void AllocAnalyzerPass::analyzeAlloc(llvm::CallInst* callInst) {

    StructType* stType;
    Function *F;
    Module *M;
    GetElementPtrInst *fromGEP = nullptr;

    M = callInst->getModule();
    F = callInst->getCalledFunction();

    if (!F) {
        if (Function *FF = dyn_cast<Function>(callInst->getCalledOperand()->stripPointerCasts())) {
            F = FF;
        }
    }

    if (F) {
        Type *baseType = F->getReturnType();
        stType = dyn_cast<StructType>(baseType);
    }

    if (!stType) {
        for (auto *callUser : callInst->users()) {
            if (auto *BCI = dyn_cast<BitCastInst>(callUser)) {
                KA_LOGS(1, "Found BitCast: "<< *BCI << "\n");
                PointerType* ptrType = dyn_cast<PointerType>(BCI->getDestTy());
                Type* baseType = ptrType->getElementType();
                stType = dyn_cast<StructType>(baseType);
                if (stType == nullptr)
                    continue;
                break;
            } else if (auto *SI = dyn_cast<StoreInst>(callUser)) {
                if (auto *GEP = dyn_cast<GetElementPtrInst>(SI->getPointerOperand())) {
                    Type *baseType = GEP->getSourceElementType();
                    stType = dyn_cast<StructType>(baseType);
                    if (stType == nullptr)
                        continue;
                    fromGEP = GEP;
                    break;
                }
            } else if (auto *LI = dyn_cast<LoadInst>(callUser)) {

            }
        }
    }

    if (!stType)
        return;

    // compose allocInst map
    string structName = getScopeName(stType, M);

    
    KA_LOGS(1, "We found " << structName << "\n");
    if (structName.find("struct") == string::npos)
        return;

    // if (fromGEP) {
    //     structName = structName + "." + to_string(fromGEP->getNumIndices());
    // }

    KA_LOGS(0, "[ALLOC] " << structName << ">");
    DEBUG_Inst(0, callInst);

    Function *body = callInst->getFunction();
    if (isPriviledged(body)) {
        outs() << body->getName() << " is priviledged function for allocating\n";
        return;
    }

    KeyStructMap::iterator it = Ctx->keyStructMap.find(structName);
    if (it != Ctx->keyStructMap.end()) {

        it->second->allocaInst.insert(callInst);
        if (fromGEP) it->second->fieldAllocGEP.insert(fromGEP->getNumIndices());

    } else {
        StructInfo *stInfo = Ctx->structAnalyzer.getStructInfo(stType, M);
        if (!stInfo) return;
        stInfo->allocaInst.insert(callInst);
        if (fromGEP) stInfo->fieldAllocGEP.insert(fromGEP->getNumIndices());
        Ctx->keyStructMap.insert(std::make_pair(structName, stInfo));
    }
}

static bool argContainType(Function *F, string typeName) {
    for (auto arg = F->arg_begin(); arg != F->arg_end(); ++arg) {
        PointerType* ptrType = dyn_cast<PointerType>(arg->getType());
        if (ptrType == nullptr)
            continue;

        Type* baseType = ptrType->getElementType();
        StructType* stType = dyn_cast<StructType>(baseType);
        if (stType == nullptr)
            continue;

        if (stType->getName() == typeName)
            return true;
    }
    return false;
}

static bool argContainMbuf(Function *F) {
    return argContainType(F, "struct.mbuf");
}

static bool addToFuncSet(Function *F, FuncSet &markedFuncSet) {
    if (F && markedFuncSet.find(F) == markedFuncSet.end()) {
        markedFuncSet.insert(F);
        return true;
    }
    return false;
}

static bool addToCallInstSet(CallInst *CI, CallInstSet &CISet) {
    if (CI && CISet.find(CI) == CISet.end()) {
        CISet.insert(CI);
        return true;
    }
    return false;
}

static bool isSndbuf(Value *V) {
    if (auto *GEP = dyn_cast<GetElementPtrInst>(V)) {
        PointerType* ptrType = dyn_cast<PointerType>(GEP->getPointerOperandType());
        if(!ptrType)
            return false;

        Type* baseType = ptrType->getElementType();
        StructType* stType = dyn_cast<StructType>(baseType);

        if (stType->getName() != "struct.socket")
            return false;

        if (GEP->getNumIndices() != 2)
            return false;

        if (auto *offset1 = dyn_cast<ConstantInt>(GEP->getOperand(1))) {
            if (auto *offset2 = dyn_cast<ConstantInt>(GEP->getOperand(2))) {
                if (offset1->getZExtValue() == 0 && offset2->getZExtValue() == 19) {
                    return true;
                }
            }
        }
    }
    return false;
}

void AllocAnalyzerPass::composeMbufLeakAPI() {

    CallInstSet LeakInst;
    FuncSet trackedFuncSet;

    for (auto M : Ctx->Callers) {
        Function *F = M.first;

        if(!addToFuncSet(F, trackedFuncSet))
            continue;

        if(!argContainMbuf(F))
            continue;

        if(argContainType(F, "struct.sockbuf")){
            // if the sockbuf is coming from sock's snd_buf
            CallerMap::iterator it = Ctx->Callers.find(F);
            if (it == Ctx->Callers.end()) {
                continue;
            }
            CallInstSet &CIS = it->second;

            for(CallInst *CI : CIS){
                // check if sockbuf is snd_buf
                for(unsigned i=0; i<CI->arg_size(); i++){
                    if(isSndbuf(CI->getArgOperand(i))){
                        addToCallInstSet(CI, LeakInst);
                        KA_LOGS(1, "LEAK API: " <<  CI->getFunction()->getName() << " --------\n");
                        KA_LOGS(1, "CallInst : ");
                        DEBUG_Inst(1, CI);
                        KA_LOGS(1, "\n");
                    }
                }
            }
        }
    }

    SmallVector<Function*, 4> workList;

    workList.clear();

    for( auto *CI : LeakInst){
        Function *F = CI->getFunction();
        if(!F)
            continue;
        workList.push_back(F);
    }

    trackedFuncSet.clear();

    while(!workList.empty()){
        Function* FF = workList.pop_back_val();

        // already checked FF
        if(!addToFuncSet(FF, trackedFuncSet))
            continue;

        // add before checking mbuf in argument
        // so as to include top APIs that don't
        // have mbuf in arguments.
        addToFuncSet(FF, Ctx->LeakAPIs);

        if(!argContainMbuf(FF))
            continue;

        CallerMap::iterator it = Ctx->Callers.find(FF);
        if (it == Ctx->Callers.end()) {
            continue;
        }
        CallInstSet &CIS = it->second;

        for (CallInst *CI : CIS) {
            Function *CallerF = CI->getParent()->getParent();
            workList.push_back(CallerF);
        }
    }

    FuncSet tmpFuncSet;
    for(auto *FF : Ctx->LeakAPIs){
        for (inst_iterator i = inst_begin(FF), e = inst_end(FF); i != e; i++) {
            Instruction* I = &*i;
            if(auto *CI = dyn_cast<CallInst>(I)){
                Function *F = CI->getCalledFunction();
                if(F && argContainMbuf(F)){
                    KA_LOGS(1, "adding " << F->getName() << " to LeakAPIs\n");
                    addToFuncSet(F, tmpFuncSet);
                }
            }
        }
    }

    for(auto *FF : tmpFuncSet){
        addToFuncSet(FF, Ctx->LeakAPIs);
    }

    for(auto *FF : Ctx->LeakAPIs){
        KA_LOGS(0, "Function : " << FF->getName() << "\n");
    }
}

void AllocAnalyzerPass::checkChannelUsageinFunc(Value* V, Value*& len, Value*& buf) {

    for (Value::use_iterator ui = V->use_begin(), ue = V->use_end();
        ui != ue; ui++) {
        if (auto* callInst = dyn_cast<CallInst>(ui->getUser())) {
            const Function* callee = callInst->getCalledFunction();
            if (callee == nullptr)
                continue;
            string calleeName = callee->getName().str();
            if (calleeName == "__memcpy" ||
                calleeName == "memcpy" ||
                calleeName == "llvm.memcpy.p0i8.p0i8.i64") {
                    len = callInst->getArgOperand(2);
                    buf = callInst->getArgOperand(1);

                    // make sure src != nla_data()
                    if(buf == V){
                        buf = nullptr;
                        len = nullptr;
                    }
                    return ;
            }

        } else if (auto* BCI = dyn_cast<BitCastInst>(ui->getUser())) {
            checkChannelUsageinFunc(BCI, len, buf);
        } else if (auto* GEP = dyn_cast<GetElementPtrInst>(ui->getUser())) {
            checkChannelUsageinFunc(GEP, len, buf);
        }
        
        if (len != nullptr && buf != nullptr)
            return;
    }
}

SmallPtrSet<Value *, 16> AllocAnalyzerPass::getAliasSet(Value *V, Function *F){

    SmallPtrSet<Value *, 16> null;
    null.clear();

    auto aliasMap = Ctx->FuncPAResults.find(F);
    if(aliasMap == Ctx->FuncPAResults.end())
        return null;

    auto alias = aliasMap->second.find(V);
    if(alias == aliasMap->second.end()){
        return null;
    }

    return alias->second;
}

void AllocAnalyzerPass::findSources(Value* V, std::vector<llvm::Value *> &srcSet, std::set<llvm::Value* > &trackedSet) {

    // Lewis: hard coded boundary to save time 
    // and avoid stack overflow, I mean that "overflow", hahaha
    // TODO: solve alias in current function
    if (trackedSet.count(V) != 0
        //  || trackedSet.size() >= 8000
        )
        return;

    trackedSet.insert(V);
    KA_LOGS(2, "FindSource: Adding ");KA_LOGV(2, V);

    // FIXME: Not examining called function inside can introduce FP
    // Lewis: this guess hits, add one chicken leg tonight!
    if (CallInst* CI = dyn_cast<CallInst>(V)) {
        // Storing callInst helps to check from value type
        srcSet.push_back(V);
        // Heuristic 1: calling to strlen()/vmalloc() isn't what we want
        const Function* callee = CI->getCalledFunction();
        if (callee != nullptr) {
            std::string calleeName = callee->getName().str();
            if (calleeName == "strlen"||
                calleeName == "vmalloc")
                return;
        }

        if(!callee) return;
        // interprocedural analysis
        StringRef tmpName = callee->getName();
        if(tmpName.lower().find("alloc") != string::npos
            || tmpName.lower().find("ALLOC") != string::npos
            || tmpName.lower().find("free") != string::npos
            || tmpName.lower().find("FREE") != string::npos
        ){
            return;
        }
        KA_LOGS(1, "Starting interprocedural analysis for "<<callee->getName().str()<<"\n");
        for(const BasicBlock &BB : *callee){
            for(const Instruction &I : BB){
                if(const ReturnInst *RI = dyn_cast<ReturnInst>(&I)){
                    if(Value *rValue = RI->getReturnValue()){
                        findSources(rValue, srcSet, trackedSet);
                    }
                }        
            }
        }
        // comment this because interprocedural analysis will taint the interesting arguments
        // for (auto AI = CI->arg_begin(), E = CI->arg_end(); AI != E; AI++) {
        //     Value* Param = dyn_cast<Value>(&*AI);
        //     findSources(Param, srcSet, trackedSet);
        // }
        return;
    }

    if(BitCastInst *BCI = dyn_cast<BitCastInst>(V)){
        srcSet.push_back(V);
        findSources(BCI->getOperand(0), srcSet, trackedSet);
        return;
    }

    if (dyn_cast<AllocaInst>(V)){
        srcSet.push_back(V);
        return;
    }

    if (dyn_cast<ConstantPointerNull>(V)){
        srcSet.push_back(V);
        return;
    }

    if (dyn_cast<Constant>(V)) {
        srcSet.push_back(V);
        return;
    }

    // Lewis: it is impossible but leave this in case
    // zipline: we need to handle this
    if (dyn_cast<GlobalVariable>(V)) {
        Constant* Ct = dyn_cast<Constant>(V);
        // if (!Ct)
        //     return;
        // srcSet.push_back(V);
        return;
    }

    // Lewis: it is impossible but leave this in case
    if (ConstantExpr* CE = dyn_cast<ConstantExpr>(V)) {
        findSources(CE->getOperand(0), srcSet, trackedSet);
        return;
    }

    if (Argument* A = dyn_cast<Argument>(V)) {
        srcSet.push_back(V);
        return; // intra-procedural

        // inter-procedural analysis begins following
        Function* callee = A->getParent();
        if (callee == nullptr)
            return;

        for (CallInst* caller : Ctx->Callers[callee]) {
            if (caller) {
                // Lewis: this should never happen
                if (A->getArgNo() >= caller->arg_size())
                    continue;
                Value* arg = caller->getArgOperand(A->getArgNo());
                if (arg == nullptr)
                    continue;

                Function* F = caller->getParent()->getParent();
                KA_LOGS(1, "<<<<<<<<< Cross Analyzing " << F->getName().str() <<  "()\n");
                KA_LOGV(1, caller);
                findSources(arg, srcSet, trackedSet);
            }
        }
    }

    if (LoadInst* LI = dyn_cast<LoadInst>(V)) {

        srcSet.push_back(V);

        // alias handling
        Function *F = LI->getFunction();

        if(!F) return;

        SmallPtrSet<Value *, 16> aliasSet;
        bool foundStore = false;

        aliasSet = getAliasSet(LI->getPointerOperand(), F);

        // add Load's pointer operand to the set
        // it may have a store successor
        aliasSet.insert(LI->getPointerOperand());

        for(auto *alias : aliasSet){
            for(auto *aliasUser : alias->users()){
                if(auto *SI = dyn_cast<StoreInst>(aliasUser)){
                    foundStore |= true;
                    KA_LOGS(1, "FindSource: resolved an alias : " << *LI << " == " << *SI << "\n");
                    findSources(SI->getValueOperand(), srcSet, trackedSet);
                }
            }
        }

        // // return because it maybe loading from a stack value
        // // since we can found a corresponding store
        // if(foundStore)
        //     return;


        findSources(LI->getPointerOperand(), srcSet, trackedSet);
        return;
    }

    if (StoreInst* SI = dyn_cast<StoreInst>(V)) {
        // findSources(SI->getValueOperand(), srcSet, trackedSet);
    }
    
    if (SelectInst* SI = dyn_cast<SelectInst>(V)) {
        findSources(SI->getTrueValue(), srcSet, trackedSet);
        findSources(SI->getFalseValue(), srcSet, trackedSet);
        return ;
    }

    if (GetElementPtrInst* GEP = dyn_cast<GetElementPtrInst>(V)) {
        // TODO f**k aliases
        KA_LOGS(1, "Here may contain an alias, please check this\n");
        DEBUG_Inst(2, GEP);
        srcSet.push_back(V);
        // Heuristic 2: first GEP is enough?
        // Lewis: Wrong
        findSources(GEP->getPointerOperand(), srcSet, trackedSet);
        return;
    }

    if (PHINode* PN = dyn_cast<PHINode>(V)) {
        for (unsigned i = 0, e = PN->getNumIncomingValues(); i != e; i++) {
            Value* IV = PN->getIncomingValue(i);
            findSources(IV, srcSet, trackedSet);
        }
        return;
    } 

    if (ICmpInst* ICmp = dyn_cast<ICmpInst>(V)) {
        for (unsigned i = 0, e = ICmp->getNumOperands(); i != e; i++) {
            Value* Opd = ICmp->getOperand(i);
            findSources(Opd, srcSet, trackedSet);
        }
        return;
    }

    if (BinaryOperator* BO = dyn_cast<BinaryOperator>(V)) {
        for (unsigned i = 0, e = BO->getNumOperands(); i != e; i++) {
            Value* Opd = BO->getOperand(i);
            if (dyn_cast<Constant>(Opd))
                continue;
            findSources(Opd, srcSet, trackedSet);
        }
        return;
    }

    if (UnaryInstruction* UI = dyn_cast<UnaryInstruction>(V)) {
        findSources(UI->getOperand(0), srcSet, trackedSet);
        return;
    }

    return;
}

// join allocInstMap and copyInstMap to compute moduleStructMap
// reverse moduleStructMap to obtain structModuleMap
// reachable analysis to compute allocSyscallMap and copySyscallMap
// join allocSyscallMap and copySyscallMap to compute keyStructList
bool AllocAnalyzerPass::doFinalization(Module* M) {

    KA_LOGS(1, "[Finalize] " << M->getModuleIdentifier() << "\n");
    ModuleStructMap::iterator it = Ctx->moduleStructMap.find(M);
    assert(it != Ctx->moduleStructMap.end() &&
        "M is not analyzed in doInitialization");

    if (it->second.size() == 0) {
        KA_LOGS(1, "No flexible structure in this module\n");
        return false;
    }
    
    KA_LOGS(1, "Building moduleStructMap ...\n");
    // moduleStructMap: map module to flexible struct "st"
    StructTypeSet tmpStructTypeSet = Ctx->moduleStructMap[M];
    for (StructTypeSet::iterator itr = tmpStructTypeSet.begin(), 
            ite = tmpStructTypeSet.end(); itr != ite; itr++) {

        StructType* st = *itr;
        std::string structName = getScopeName(st, M);
        
        InstMap::iterator liit = Ctx->copyInstMap.find(structName);
        // XXX 
        // AllocInstMap::iterator aiit = Ctx->allocInstMap.find(structName);

        // either leak or alloc or both
        if (liit == Ctx->copyInstMap.end() )
            // XXX    
            //  || aiit == Ctx->allocInstMap.end() )
            Ctx->moduleStructMap[M].erase(st);
    }

    if (Ctx->moduleStructMap[M].size() == 0) {
        KA_LOGS(1, "Actually no flexible structure in this module\n");
        return false;
    }


    KA_LOGS(1, "Building structModuleMap ...\n");
    // structModuleMap: map flexible struct "st" to module
    for (StructTypeSet::iterator itr = Ctx->moduleStructMap[M].begin(), 
            ite = Ctx->moduleStructMap[M].end(); itr != ite; itr++) {

        StructType* st = *itr;
        std::string structName = getScopeName(st, M);

        StructModuleMap::iterator sit = Ctx->structModuleMap.find(structName);
        if (sit == Ctx->structModuleMap.end()) {
            ModuleSet moduleSet;
            moduleSet.insert(M);
            Ctx->structModuleMap.insert(std::make_pair(structName, moduleSet)) ;
        } else {
            sit->second.insert(M);
        }
    }

    KA_LOGS(1, "Building copySyscallMap & allocSyscallMap ...\n");
    // copySyscallMap: map structName to syscall reaching leak sites
    // allocSyscallMap: map structName to syscall reaching allocation sites
    for (StructTypeSet::iterator itr = Ctx->moduleStructMap[M].begin(),
            ite = Ctx->moduleStructMap[M].end(); itr != ite; itr++) {

        StructType* st = *itr;
        std::string structName = getScopeName(st, M);

        // copySyscallMap
        // XXX
        KA_LOGS(1, "Dealing with leaking: " << structName << "\n");
        InstMap::iterator liit = Ctx->copyInstMap.find(structName);
        SyscallMap::iterator lsit = Ctx->copySyscallMap.find(structName);
        if (liit != Ctx->copyInstMap.end() &&
            lsit == Ctx->copySyscallMap.end() // to avoid redundant computation
            ) {
            for (auto I : liit->second) {

                Function* F = I->getParent()->getParent();
                FuncSet syscallSet = reachableSyscall(F);
                if (syscallSet.size() == 0)
                    continue;

                SyscallMap::iterator lsit = Ctx->copySyscallMap.find(structName);
                if (lsit == Ctx->copySyscallMap.end())
                    Ctx->copySyscallMap.insert(std::make_pair(structName, syscallSet));
                else
                    for (auto F : syscallSet)
                        lsit->second.insert(F);
            }
        }

        // allocSyscallMap
        // XXX
        /*
        KA_LOGS(1, "Dealing with allocating: " << structName << "\n");
        AllocInstMap::iterator aiit = Ctx->allocInstMap.find(structName);
        AllocSyscallMap::iterator asit = Ctx->allocSyscallMap.find(structName);
        if (aiit != Ctx->allocInstMap.end() &&
            asit == Ctx->allocSyscallMap.end()
            ) {
            for (auto I : aiit->second) {

                Function* F = I->getParent()->getParent();
                FuncSet syscallSet = reachableSyscall(F);
                if (syscallSet.size() == 0)
                    continue;

                AllocSyscallMap::iterator asit = Ctx->allocSyscallMap.find(structName);
                if (asit == Ctx->allocSyscallMap.end())
                    Ctx->allocSyscallMap.insert(std::make_pair(structName, syscallSet));
                else
                    for (auto F : syscallSet)
                        asit->second.insert(F);
            }
        }
        */
        
    }

    KA_LOGS(1, "Building keyStructList ...\n");
    for (StructTypeSet::iterator itr = Ctx->moduleStructMap[M].begin(), 
            ite = Ctx->moduleStructMap[M].end(); itr != ite; itr++) {

        StructType* st = *itr;
        std::string structName = getScopeName(st, M);

        SyscallMap::iterator lsit = Ctx->copySyscallMap.find(structName);
        // XXX 
        // AllocSyscallMap::iterator asit = Ctx->allocSyscallMap.find(structName);
        
        if (lsit == Ctx->copySyscallMap.end())
            //XXX    
            // || asit == Ctx->allocSyscallMap.end())
            continue;

        KeyStructList::iterator tit = Ctx->keyStructList.find(structName);
        if (tit == Ctx->keyStructList.end()) {
            InstSet instSet;
            for (auto I : Ctx->copyInstMap[structName])
                instSet.insert(I);
            Ctx->keyStructList.insert(std::make_pair(structName, instSet));

        } else {
            for (auto I : Ctx->copyInstMap[structName])
                tit->second.insert(I);
        }
    }
    return false;
}

FuncSet AllocAnalyzerPass::getSyscalls(Function *F){
    ReachableSyscallCache::iterator it = reachableSyscallCache.find(F);
    if (it != reachableSyscallCache.end())
        return it->second;
    FuncSet null;
    return null;
}

FuncSet AllocAnalyzerPass::reachableSyscall(llvm::Function* F) {

    ReachableSyscallCache::iterator it = reachableSyscallCache.find(F);
    if (it != reachableSyscallCache.end())
        return it->second;

    FuncSet reachableFuncs;
    reachableFuncs.clear();

    FuncSet reachableSyscalls;
    reachableSyscalls.clear();

    SmallVector<Function*, 4> workList;
    workList.clear();
    workList.push_back(F);

    while (!workList.empty()) {
        Function* F = workList.pop_back_val();
        if (!reachableFuncs.insert(F).second)
            continue;

        if(reachableSyscallCache.find(F) != reachableSyscallCache.end()){
            FuncSet RS = getSyscalls(F);
            for(auto *RF : RS){
                reachableFuncs.insert(RF);
            }
            continue;
        }

        CallerMap::iterator it = Ctx->Callers.find(F);
        if (it != Ctx->Callers.end()) {
            for (auto calleeInst: it->second) {
                Function* F = calleeInst->getParent()->getParent();
                workList.push_back(F);
            }
        }
    }

    for (auto F : reachableFuncs) {
        StringRef funcNameRef = F->getName();
        std::string funcName = "";
        if (funcNameRef.startswith("__sys_")) {
            funcName = "sys_" + funcNameRef.str().substr(6);
        } else if (funcNameRef.startswith("__x64_sys_")) {
	    funcName = "sys_" + funcNameRef.str().substr(9);
	} else if (funcNameRef.startswith("__ia32_sys")) {
	    funcName = "sys_" + funcNameRef.str().substr(10);
	} else if (funcNameRef.startswith("__se_sys")) {
	    funcName = "sys_" + funcNameRef.str().substr(8);
	}

	if(funcName != "") {
            if (std::find(rootSyscall.begin(), rootSyscall.end(), funcName) ==
                rootSyscall.end()) {
                reachableSyscalls.insert(F);
            }
	}
    }

    reachableSyscallCache.insert(std::make_pair(F, reachableSyscalls));
    return  reachableSyscalls;
}
