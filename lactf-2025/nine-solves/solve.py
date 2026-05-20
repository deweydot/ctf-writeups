def collatz(x, n=0):
    if x == 1:
        return n
    elif x % 2 == 0:
        return collatz(x >> 1, n+1)
    else:
        return collatz(x * 3 + 1, n+1)
    
yi = [0x1b, 0x26, 0x57, 0x5f, 0x76, 0x09]
res = {}

for num in yi:
    for i in range(32, 127):
        if collatz(i) == num:
            res[num] = chr(i)
            break

print(''.join(res.values()))