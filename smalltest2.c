int h(int x) {
    return x;
}

int f(int a) {
    int b;
    if (a == 0) {
        b = h(1);
    } else if (a * a == 0) { /*only when a*a overflows*/
        b = h(2);
    } else {
        b = 0;
    }
    return b;
}

int trip_breaker() {
    return 1;
}

int main(int argc, char *argv[]) {
    int breaker = 0;
    int authz = f(argc);
    if (authz == 1) {
        breaker = trip_breaker();
    } else if (authz == 2) {
        breaker = trip_breaker();
    }
    return breaker;
}
