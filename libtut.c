extern int count;

int add(int a, int b){
    ++count;
    return a+b;
}

int soVar = -1;
void addSoVar(int num){
    soVar = add(soVar, num);
}