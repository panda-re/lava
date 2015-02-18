#include "llvm/Pass.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Support/raw_ostream.h"
#include <vector>

using namespace llvm;

namespace {
    struct Stringcopy: public FunctionPass {
        static char ID;
        Stringcopy(): FunctionPass(ID) {}

        bool runOnFunction(Function &F) override {
            bool modified = false;

            Module *M = F.getParent();

            /* Create strcpy function */
            std::vector<Type *> ParamTy;
            ParamTy.push_back(PointerType::getUnqual(Type::getInt8Ty(M->getContext())));
            ParamTy.push_back(PointerType::getUnqual(Type::getInt8Ty(M->getContext())));
            ParamTy.push_back(Type::getInt64Ty(M->getContext()));

            Function * strncpyFunc = M->getFunction("__strncpy_chk");
            if (!strncpyFunc)
                return modified;
            Type *strcpyRT = strncpyFunc->getReturnType();
            FunctionType *strcpyFT = FunctionType::get(strcpyRT, ParamTy, false);
            Constant * strcpyFunc = M->getOrInsertFunction("__strcpy_chk", strcpyFT);

            /* Find functions calls to modify */
            std::vector<Instruction *> toModify;
            for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I) {
                if (! (isa<CallInst>(&*I) || isa<InvokeInst>(&*I) ))
                    continue;
                CallInst * CI = dyn_cast<CallInst>(&*I);
                Function * CalledFunc = CI->getCalledFunction();

                if (CalledFunc == 0 || !CalledFunc->hasName())
                    continue;
                if (CalledFunc->getName() != "__strncpy_chk")
                    continue;

                toModify.push_back(CI);
            }

            /* Replace strncpy with strcpy */
            for (std::vector<Instruction *>::iterator it = toModify.begin(); it != toModify.end(); ++it) {
                Instruction *I = *it;

                std::vector<Value *> Params;
                Params.push_back(I->getOperand(0));
                Params.push_back(I->getOperand(1));
                Params.push_back(I->getOperand(2));

                CallInst *strcpyCallInst = CallInst::Create(strcpyFunc, Params, "", I);
                I->replaceAllUsesWith(strcpyCallInst);
                I->eraseFromParent();  
                modified = true;
            }
        
            return modified;
        }

    };
}


char Stringcopy::ID = 0;
static RegisterPass<Stringcopy> X("strcpy", "Replacing Strncpy Pass");

