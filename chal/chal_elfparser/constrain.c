#include <stdio.h>
#include <set>
#include <iostream>

#define MOD(X, Y) ((X)%(Y))
#define P2(X, Y) MOD((MOD((X), (Y))*MOD((X), (Y))), (Y))
#define MULTI(X, Y, Z) MOD((MOD((X), (Z))*MOD((Y), (Z))), (Z))
#define P4(X, Y) P2(P2(X, Y), Y)
#define P5(X, Y) MULTI(P4(X, Y), (X), (Y))
#define P8(X, Y) P4(P4(X, Y), Y)
#define P11(X, Y) MULTI(P2(P5(X,Y),Y), (X), (Y))
#define P16(X, Y) P8(P8(X, Y), Y)

void printIntersect(std::initializer_list<std::set<int>>s) {
    std::set<int> intersectset;
    for (auto ss = s.begin(); ss != s.end(); ss++) {
        if (ss == s.begin()) {
            intersectset = *ss;
            continue;
        }
        for (auto x = intersectset.begin(); x != intersectset.end();)
            if ((*ss).find(*x) == (*ss).end())
                x = intersectset.erase(x);
            else
                x++;
    }
    for (auto x : intersectset)
        printf("%x\n", x);
}

void printExclude(std::initializer_list<std::set<int>>s) {
    std::set<int> xset;
    for (auto ss = s.begin(); ss != s.end(); ss++) {
        if (ss == s.begin()) {
            xset = *ss;
            continue;
        }
        for (auto x = xset.begin(); x != xset.end();)
            if ((*ss).find(*x) != (*ss).end())
                x = xset.erase(x);
            else
                x++;
    }
    for (auto x : xset)
        printf("%x\n", x);
}

void floatrule() {
    std::set<int> set1, set2, set3, set4, set5, set6;
    float i;
    for (int j = 0; j < 0x10000; j++) {
        //int tmp = (j<<16);
        int tmp = j&0xffff;
        //if ((i=tmp,((P8((*(int*)(&i))>>24,37)*P2((*(int*)(&i))>>24,23))&0xff)==0))
        //if ((i=tmp&0xffff,i=(__builtin_powif(i,8)+__builtin_powif(i,3)),((*(int*)&i)&0x50505050)==0x40000040))
        //if ((i=tmp,i=(__builtin_powif(i, (tmp>>4)&0xf)),(((*(int*)(&i))>>28)&0xf)==(((*(int*)(&i))>>24)&0xf)))
        //if ((i=(tmp>>16),((*(int*)(&i))&0xf000000)==0x5000000) && (i=(tmp>>16),((*(int*)(&i))&0xf000)<0x7000) && ((int)(tmp>>16)>0))
        //if ((i=((tmp>>16)&0xffff),((P8((*(int*)(&i))>>24,37)^P2((*(int*)(&i))>>24,23))&0xff)==0) && (i=((tmp>>16)&0xffff),i=(__builtin_powif(i,8)+__builtin_powif(i,3)),((*(int*)&i)&0x50505050)==0x40000040))
        //if ((((tmp>>16)*(tmp>>16)+(tmp>>16)+1)&7==5) && (i=(tmp>>16),((P8((*(int*)(&i))>>24,37)^P2((*(int*)(&i))>>24,23))&0xff)==0))
        //if ((__builtin_clz(tmp)) && ((P8(tmp>>16, 349)*P2(tmp>>16, 439))&0xf == (P8(tmp>>16, 349)+P2(tmp>>16, 439))&0xf))
        //if ((i=((tmp>>16)&0xffff),i=(__builtin_powif(i,8)+__builtin_powif(i,3)),((*(int*)&i)&0x50505050)==0x40000040) && (__builtin_clz(tmp)))
        //
        //if ((i=(tmp>>16),i=(__builtin_powif(i,7)),(*(int*)&i)&1) && (i=((tmp>>16)^0x5555),__builtin_clz(*(int*)&i)))
        //if ((i=(tmp>>16),__builtin_ffs(*(int*)&i)>15) && (i=(tmp>>16),__builtin_popcount(*(int*)&i)>11))
        //if ((i=(tmp>>16),__builtin_ffs(*(int*)&i)>15) && (i=((tmp>>16)^0x5555),__builtin_clz(*(int*)&i)))
        //if ((i=(tmp>>16),__builtin_popcount(*(int*)&i)>11) && (i=(tmp>>16),i=(__builtin_powif(i,7)),(*(int*)&i)&1))
        //if ((i=(tmp>>16),i=__builtin_powif(i,__builtin_ctz(*(int*)&i)),__builtin_parity(*(int*)&i)) && (i=(tmp>>16),i*=1337,(*(int*)&i)&0xf0==0xf0))
        //if ((i=(tmp>>16),i+=0xdeadbeef,(*(int*)&i)%10>5) && (i=(tmp>>16),i*=1337,(*(int*)&i)&0xf0==0xf0))
        //if ((i=(tmp>>16)^0x5555,i=(__builtin_powif(i,__builtin_popcount(*(int*)&i)%7)),(__builtin_popcount(*(int*)&i)&0xf)==7) && (i=(tmp>>16),i/=0xbeefdead,(*(int*)&i)>5))
        //
        if ((!(__builtin_popcount(tmp&0x5aa5)&2)) && (__builtin_clz(tmp<<16)))
            set1.emplace(j);
        if ((i=(tmp&0xffff),__builtin_ffs(*(int*)&i)>15) && (i=(tmp&0xffff),__builtin_popcount(*(int*)&i)>11))
            set2.emplace(j);
        if ((i=(tmp&0xffff),((*(int*)(&i))&0xf000000)==0x5000000) && (i=(tmp&0xffff),((*(int*)(&i))&0xf000)<0x7000))
            set3.emplace(j);
        if (((((tmp&0xffff)*0xfe)&0xf0f0)==0xf0f0) && (__builtin_ffs(tmp)>3))
            set4.emplace(j);
        if ((i=(tmp&0xffff),i+=0xdeadbeef,(*(int*)&i)%10>5) && (i=(tmp&0xffff),i*=1337,(*(int*)&i)&0xf0==0xf0))
            set5.emplace(j);
        if ((i=((tmp)&0xffff),i=(__builtin_powif(i,8)+__builtin_powif(i,3)),((*(int*)&i)&0x50505050)==0x40000040) && (__builtin_clz(tmp<<16)))
            set6.emplace(j);
    }

    //printIntersect({set5, set1, set3});
    //printIntersect({set1, set3});
    //printIntersect({set3});
    //printIntersect({set5, set4});

    //printExclude({set4, set5, set1, set3, set2, set6});

    //printExclude({set5, set1, set3});
    //printExclude({set3, set1, set5});
    //printExclude({set1, set3, set5});

    //printf("everything:\n");
    std::set<int> all;
    all.insert(set1.begin(), set1.end());
    all.insert(set2.begin(), set2.end());
    all.insert(set3.begin(), set3.end());
    all.insert(set4.begin(), set4.end());
    all.insert(set5.begin(), set5.end());
    all.insert(set6.begin(), set6.end());
    std::cout << "[";
    for (int c : all)
        if (c != 0xcb88)
            std::cout << c << ", ";
    std::cout << "]\n";
}
void floattest(int i) {
    float f = i;
    printf("%x\n", (f=(i),f=__builtin_bswap16(*(int*)(&f)),f));
}

void power() {
    for (int j = 0; j < 0x10000; j++) {
        int tmp = (j<<16);
        //if ((((P16(tmp>>16, 0x1337)^P5(tmp>>16, 0x1337))&0xf0)==0xf0) && (((P8(tmp>>24, 137)+P11(tmp>>24, 137))&0x55)==0x55))
        //if ((((P5(tmp>>24, 7557)*P4(tmp>>24, 4657))&0xff)!=0) && (((P8(tmp>>16, 349)+P2(tmp>>16, 439))&0xff)==0x55))
            printf("%x\n", j);
    }
}

int main() {
    int bug = 0x4988;
    floatrule();
    //floattest(0x0804);
    return 0;
}
