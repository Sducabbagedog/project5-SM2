import random
from math import gcd, ceil, log
from gmssl import sm3

class SM2:
    def __init__(self):
        # 椭圆曲线系统参数
        self.p = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
        self.a = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
        self.b = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
        self.h = 1
        self.Gx = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
        self.Gy = 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2
        self.n = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
        
        # 接收方B的公私钥
        self.PBx = 0x435B39CCA8F3B508C1488AFC67BE491A0F7BA07E581A0E4849A5CF70628A7E0A
        self.PBy = 0x75DDBA78F15FEECB4C7895E2C1CDF5FE01DEBB2CDBADF45399CCF77BBA076A42
        self.dB = 0x1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0
        
        # 计算域元素字节长度
        self.t = ceil(log(self.p, 2))
        self.l = ceil(self.t / 8)
    
    def int_to_bytes(self, x, k):
        """整数转字节串"""
        if pow(256, k) <= x:
            raise ValueError("目标字节串长度过短")
        return x.to_bytes(k, byteorder='big')
    
    def bytes_to_int(self, M):
        """字节串转整数"""
        return int.from_bytes(M, byteorder='big')
    
    def fielde_to_bytes(self, e):
        """域元素转字节串"""
        return self.int_to_bytes(e, self.l)
    
    def bytes_to_fielde(self, M):
        """字节串转域元素"""
        return self.bytes_to_int(M)
    
    def point_to_bytes(self, P):
        """点转字节串（未压缩形式）"""
        xp, yp = P
        x_bytes = self.fielde_to_bytes(xp)
        y_bytes = self.fielde_to_bytes(yp)
        return b'\x04' + x_bytes + y_bytes
    
    def bytes_to_point(self, s):
        """字节串转点"""
        if len(s) % 2 == 0 or s[0] != 4:
            raise ValueError("无效的点表示")
        l = (len(s) - 1) // 2
        x = self.bytes_to_fielde(s[1:1+l])
        y = self.bytes_to_fielde(s[1+l:1+2*l])
        return (x, y)
    
    def fielde_to_bits(self, a):
        """域元素转比特串"""
        return bin(a)[2:].zfill(self.t)
    
    def kdf(self, Z, klen):
        """密钥派生函数"""
        v = 256  # SM3输出长度
        if klen >= (pow(2, 32) - 1) * v:
            raise ValueError("klen过大")
        
        ct = 1
        l = ceil(klen / v)
        Ha = []
        
        for _ in range(l):
            s = Z + ct.to_bytes(4, byteorder='big')
            s_list = list(s)
            hash_hex = sm3.sm3_hash(s_list)
            hash_bin = bin(int(hash_hex, 16))[2:].zfill(256)
            Ha.append(hash_bin)
            ct += 1
        
        k = ''.join(Ha)[:klen]
        return k
    
    def mod_inverse(self, a, m):
        """模逆计算"""
        if gcd(a, m) != 1:
            return None
        return pow(a, -1, m)
    
    def point_add(self, P, Q):
        """椭圆曲线点加"""
        if P == 0: return Q
        if Q == 0: return P
        x1, y1 = P
        x2, y2 = Q
        
        if x1 == x2:
            if y1 != y2:
                return 0  # 无穷远点
            return self.point_double(P)
        
        l = ((y2 - y1) * self.mod_inverse(x2 - x1, self.p)) % self.p
        x3 = (l*l - x1 - x2) % self.p
        y3 = (l*(x1 - x3) - y1) % self.p
        return (x3, y3)
    
    def point_double(self, P):
        """椭圆曲线二倍点"""
        if P == 0: return P
        x1, y1 = P
        l = ((3*x1*x1 + self.a) * self.mod_inverse(2*y1, self.p)) % self.p
        x3 = (l*l - 2*x1) % self.p
        y3 = (l*(x1 - x3) - y1) % self.p
        return (x3, y3)
    
    def point_mult(self, k, P):
        """椭圆曲线多倍点计算"""
        Q = 0  # 无穷远点
        bits = bin(k)[2:]
        
        for bit in bits:
            Q = self.point_double(Q)
            if bit == '1':
                Q = self.point_add(Q, P)
        return Q
    
    def on_curve(self, P):
        """验证点是否在椭圆曲线上"""
        if P == 0: return True
        x, y = P
        left = (y * y) % self.p
        right = (x*x*x + self.a*x + self.b) % self.p
        return left == right
    
    def encrypt(self, message):
        """SM2加密算法"""
        # 步骤A1：生成随机数k
        k = random.randint(1, self.n-1)
        print(f"生成随机数k: {hex(k)}")
        
        # 步骤A2：计算椭圆曲线点C1=[k]G
        C1 = self.point_mult(k, (self.Gx, self.Gy))
        print(f"C1点坐标: ({hex(C1[0])}, {hex(C1[1])})")
        
        # 步骤A3：计算椭圆曲线点S = [h]PB
        PB = (self.PBx, self.PBy)
        S = self.point_mult(self.h, PB)
        if S == 0:
            raise ValueError("S是无穷远点")
        
        # 步骤A4：计算椭圆曲线点[k]PB
        P2 = self.point_mult(k, PB)
        x2, y2 = P2
        
        # 步骤A5：计算t=KDF(x2 ∥ y2, klen)
        klen = len(message) * 8  # 明文比特长度
        Z = x2.to_bytes(self.l, 'big') + y2.to_bytes(self.l, 'big')
        t = self.kdf(Z, klen)
        if int(t, 2) == 0:
            raise ValueError("KDF生成了全零串")
        
        # 步骤A6：计算C2 = M ⊕ t
        M_int = int.from_bytes(message.encode('ascii'), 'big')
        t_int = int(t, 2)
        C2 = M_int ^ t_int
        
        # 步骤A7：计算C3 = Hash(x2 ∥ M ∥ y2)
        M_bytes = message.encode('ascii')
        hash_input = x2.to_bytes(self.l, 'big') + M_bytes + y2.to_bytes(self.l, 'big')
        C3 = sm3.sm3_hash(list(hash_input))
        
        # 步骤A8：输出密文C = C1 ∥ C2 ∥ C3
        C1_bytes = self.point_to_bytes(C1)
        C2_bytes = C2.to_bytes((klen + 7) // 8, 'big')
        C3_bytes = bytes.fromhex(C3)
        
        ciphertext = C1_bytes + C2_bytes + C3_bytes
        return ciphertext.hex()
    
    def decrypt(self, ciphertext):
        """SM2解密算法"""
        cipher_bytes = bytes.fromhex(ciphertext)
        
        # 步骤B1：从C中取出C1并验证
        C1_len = 1 + 2 * self.l
        C1_bytes = cipher_bytes[:C1_len]
        C1 = self.bytes_to_point(C1_bytes)
        if not self.on_curve(C1):
            raise ValueError("C1不在椭圆曲线上")
        
        # 步骤B2：计算S=[h]C1
        S = self.point_mult(self.h, C1)
        if S == 0:
            raise ValueError("S是无穷远点")
        
        # 步骤B3：计算[dB]C1=(x2,y2)
        P2 = self.point_mult(self.dB, C1)
        x2, y2 = P2
        
        # 步骤B4：计算t=KDF(x2 ∥ y2, klen)
        C3_len = 32  # SM3哈希长度
        C2_len = len(cipher_bytes) - C1_len - C3_len
        klen = C2_len * 8
        Z = x2.to_bytes(self.l, 'big') + y2.to_bytes(self.l, 'big')
        t = self.kdf(Z, klen)
        if int(t, 2) == 0:
            raise ValueError("KDF生成了全零串")
        
        # 步骤B5：计算M′ = C2 ⊕ t
        C2_bytes = cipher_bytes[C1_len:C1_len+C2_len]
        C2_int = int.from_bytes(C2_bytes, 'big')
        t_int = int(t, 2)
        M_prime_int = C2_int ^ t_int
        M_prime = M_prime_int.to_bytes(C2_len, 'big').decode('ascii', errors='replace')
        
        # 步骤B6：验证u = Hash(x2 ∥ M′ ∥ y2) 是否等于 C3
        M_prime_bytes = M_prime.encode('ascii')
        hash_input = x2.to_bytes(self.l, 'big') + M_prime_bytes + y2.to_bytes(self.l, 'big')
        u = sm3.sm3_hash(list(hash_input))
        C3_bytes = cipher_bytes[-C3_len:]
        if u != C3_bytes.hex():
            raise ValueError("C3验证失败")
        
        return M_prime

if __name__ == "__main__":
    print("SM2椭圆曲线公钥密码算法".center(80, '='))
    sm2 = SM2()
    
    # 显示系统参数
    print("\n椭圆曲线系统参数:")
    print(f"p: {hex(sm2.p)}")
    print(f"a: {hex(sm2.a)}")
    print(f"b: {hex(sm2.b)}")
    print(f"Gx: {hex(sm2.Gx)}")
    print(f"Gy: {hex(sm2.Gy)}")
    print(f"n: {hex(sm2.n)}")
    
    # 显示密钥信息
    print("\n接收方B的公私钥:")
    print(f"PBx: {hex(sm2.PBx)}")
    print(f"PBy: {hex(sm2.PBy)}")
    print(f"dB: {hex(sm2.dB)}")
    
    # 获取明文
    message = input("\n请输入要加密的明文: ")
    
    # 加密
    print("\n加密过程:")
    ciphertext = sm2.encrypt(message)
    print(f"密文: {ciphertext}")
    
    # 解密
    print("\n解密过程:")
    try:
        plaintext = sm2.decrypt(ciphertext)
        print(f"解密结果: {plaintext}")
        
        # 验证
        print("\n验证结果:")
        print(f"原始明文: '{message}'")
        print(f"解密明文: '{plaintext}'")
        print("解密成功!" if message == plaintext else "解密失败!")
    except Exception as e:
        print(f"解密错误: {str(e)}")