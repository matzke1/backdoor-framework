int f(int a) {
    int b = 0, i;
    for (i=0; i<a; ++i)
        ++b;
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
