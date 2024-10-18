#ifndef LL_H
#define LL_H

#define ll_fpush(LL,E)\
    do {\
        if (LL == NULL) {\
            LL = E;\
            LL->ll_next = LL;\
            LL->ll_prev = LL;\
        } else {\
            LL->ll_prev->ll_next = E;\
            E->ll_prev = LL->ll_prev;\
            E->ll_next = LL;\
            LL->ll_prev = E;\
        }\
    } while(0)

#define ll_bpush(LL,E) \
    do {\
        ll_fpush(LL,E); \
        LL = E;\
    } while(0);

#define ll_fpop(LL,E)\
    do {\
        if (LL == NULL || LL->ll_next == LL) {\
            E = LL;\
            LL = NULL;\
        } else {\
            E = LL->ll_prev;\
            E->ll_prev->ll_next = LL;\
            LL->ll_prev = E->ll_prev;\
        }\
    } while(0);

#define ll_bpop(LL,E) \
    do {\
        if (LL == NULL || LL->ll_next == LL) {\
            E = LL;\
            LL = NULL;\
        } else {\
            LL = LL->ll_prev;\
            ll_fpop(LL,E);\
        }\
    } while(0);

#define ll_foreach(LL,E,I) \
    for( E = LL, I = 0; E && ( E != LL || I == 0 ); E = E->ll_next, I++ )

#endif


// A B C D