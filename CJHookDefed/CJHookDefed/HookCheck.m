
//
//  HookCheck.m
//  LuYiFu
//
//  Created by 峰 on 2020/11/25.
//  Copyright © 2020 Oila. All rights reserved.
//

#import "HookCheck.h"

#import <mach-o/dyld.h>
#import <objc/runtime.h>
#import "fishhook.h"

static const char * DefendSelectArray[] = {"completeCheck","isCryptidEncrypted","isJailbroken1","isJailbroken2","isJailbroken3","whitelistCheck","getWhitelist","isDebugger","debugCheck","openAntiDebugWithOutMonitorException","_openAllMonitor"};


@implementation HookCheck

void (* orig_exchangeImple)(Method _Nonnull m1, Method _Nonnull m2);
IMP _Nonnull (* orig_setImple)(Method _Nonnull m, IMP _Nonnull imp);
IMP _Nonnull (* getIMP)(Method _Nonnull m);


+ (void)load{
    if(TARGET_IPHONE_SIMULATOR)return;
    struct rebinding exchange_rebinding;
    exchange_rebinding.name = "method_exchangeImplementations";
    exchange_rebinding.replacement = hook_exchangeImple;
    exchange_rebinding.replaced = (void *)&orig_exchangeImple;
    
    struct rebinding setImple_rebinding;
    setImple_rebinding.name = "method_setImplementation";
    setImple_rebinding.replacement = hook_setImple;
    setImple_rebinding.replaced = (void *)&orig_setImple;
    
    struct rebinding rebindings[] = {exchange_rebinding,setImple_rebinding};
    rebind_symbols(rebindings, 2);
}

void hook_exchangeImple(Method _Nonnull orig_method, Method _Nonnull changed_method){
    if(orig_method){
        SEL sel = method_getName(orig_method);
        bool in_def = in_defend_sel((char *)[NSStringFromSelector(sel) UTF8String]);
        if(in_def){
            [[NSUserDefaults standardUserDefaults] setBool:YES forKey:fhKey];
            [[NSUserDefaults standardUserDefaults] synchronize];
            return;
        }
    }
    orig_exchangeImple(orig_method,changed_method);
}
void hook_setImple(Method _Nonnull method, IMP _Nonnull imp){
    if(method){
        SEL sel = method_getName(method);
        bool in_def = in_defend_sel((char *)[NSStringFromSelector(sel) UTF8String]);
        if(in_def){
            [[NSUserDefaults standardUserDefaults] setBool:YES forKey:fhKey];
            [[NSUserDefaults standardUserDefaults] synchronize];
            return;
        }
    }
    orig_setImple(method,imp);
}

bool in_defend_sel(char *selStr){
    for (int i = 0;i < sizeof(DefendSelectArray) / sizeof(char *);i++) {
        if(0 == strcmp(selStr, DefendSelectArray[i])){
            return true;
        }
    }
    return false;
}

@end
