import random
from math import gcd, ceil, log
from gmssl import sm3
import hashlib

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
        
        # 计算域元素字节长度
        self.t = ceil(log(self.p, 2))
        self.l = ceil(self.t / 8)
    
    def int_to_bytes(self, x, k=None):
        """整数转字节串"""
        if k is None:
            k = (x.bit_length() + 7) // 8 or 1
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
        if s[0] != 4:
            raise ValueError("不支持压缩点格式")
        l = (len(s) - 1) // 2
        x = self.bytes_to_fielde(s[1:1+l])
        y = self.bytes_to_fielde(s[1+l:1+2*l])
        return (x, y)
    
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
        """椭圆曲线多倍点计算（标量乘法）"""
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
    
    def compute_ZA(self, ID, public_key):
        """
        计算ZA = H256(ENTL_A || ID_A || a || b || xG || yG || xA || yA)
        参数:
            ID: 用户身份标识 (字符串)
            public_key: 公钥 (元组 (x, y))
        """
        # 计算ID长度
        entl = len(ID.encode('utf-8')) * 8
        entl_bytes = entl.to_bytes(2, byteorder='big')
        
        # 准备哈希输入
        a_bytes = self.fielde_to_bytes(self.a)
        b_bytes = self.fielde_to_bytes(self.b)
        xG_bytes = self.fielde_to_bytes(self.Gx)
        yG_bytes = self.fielde_to_bytes(self.Gy)
        xA, yA = public_key
        xA_bytes = self.fielde_to_bytes(xA)
        yA_bytes = self.fielde_to_bytes(yA)
        
        # 构造哈希输入
        hash_input = (entl_bytes + ID.encode('utf-8') + a_bytes + b_bytes + 
                     xG_bytes + yG_bytes + xA_bytes + yA_bytes)
        
        # 计算SM3哈希
        hash_value = sm3.sm3_hash(list(hash_input))
        return bytes.fromhex(hash_value)
    
    def sign(self, message, private_key, public_key, ID="ALICE123@YAHOO.COM"):
        """
        SM2数字签名生成
        参数:
            message: 待签名的消息 (字符串)
            private_key: 私钥 (整数)
            public_key: 公钥 (元组 (x, y))
            ID: 用户身份标识 (字符串)
        返回:
            签名 (r, s)
        """
        # 步骤1: 计算ZA。构造M~ = ZA || M
        ZA = self.compute_ZA(ID, public_key)
        M = message.encode('utf-8')
        M_tilde = ZA + M
        
        # 步骤2: 计算e = Hv(M~)
        e_hash = sm3.sm3_hash(list(M_tilde))
        e = int(e_hash, 16) % self.n
        
        # 步骤3: 生成随机数k ∈ [1, n-1]
        while True:
            k = random.randint(1, self.n-1)
            #k=0x6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F

            # 步骤4: 计算椭圆曲线点(x1, y1) = [k]G
            P = self.point_mult(k, (self.Gx, self.Gy))
            if P == 0:
                continue
            x1, y1 = P
            
            # 步骤5: 计算r = (e + x1) mod n
            r = (e + x1) % self.n
            if r == 0 or r + k == self.n:
                continue
            
            # 步骤6: 计算s = ((1 + dA)^-1 * (k - r * dA)) mod n
            dA = private_key
            s = (self.mod_inverse(1 + dA, self.n) * (k - r * dA) )% self.n
            if s == 0:
                continue
                
            return (r, s)
    
    def sign_att(self, message, private_key, public_key,k_set,ID="ALICE123@YAHOO.COM"):
        """
        SM2数字签名生成
        参数:
            message: 待签名的消息 (字符串)
            private_key: 私钥 (整数)
            public_key: 公钥 (元组 (x, y))
            k_set: 手动设置的k (整数)
            ID: 用户身份标识 (字符串)
        返回:
            签名 (r, s)
        """
        # 步骤1: 计算ZA。构造M~ = ZA || M
        ZA = self.compute_ZA(ID, public_key)
        M = message.encode('utf-8')
        M_tilde = ZA + M
        
        # 步骤2: 计算e = Hv(M~)
        e_hash = sm3.sm3_hash(list(M_tilde))
        e = int(e_hash, 16) % self.n
        
        # 步骤3: 生成随机数k ∈ [1, n-1]
        while True:
            #k = random.randint(1, self.n-1)
            #k=0x6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F
            k=k_set
            
            # 步骤4: 计算椭圆曲线点(x1, y1) = [k]G
            P = self.point_mult(k, (self.Gx, self.Gy))
            if P == 0:
                continue
            x1, y1 = P
            
            # 步骤5: 计算r = (e + x1) mod n
            r = (e + x1) % self.n
            if r == 0 or r + k == self.n:
                continue
            
            # 步骤6: 计算s = ((1 + dA)^-1 * (k - r * dA)) mod n
            dA = private_key
            s = (self.mod_inverse(1 + dA, self.n) * (k - r * dA) )% self.n
            if s == 0:
                continue
                
            return (r, s)
    
    
    def verify(self, message, signature, public_key, ID="ALICE123@YAHOO.COM"):
        """
        SM2数字签名验证
        参数:
            message: 原始消息 (字符串)
            signature: 签名 (元组 (r, s))
            public_key: 公钥 (元组 (x, y))
            ID: 用户身份标识 (字符串)
        返回:
            验证结果 (布尔值)
        """
        r, s = signature
        xA, yA = public_key
        
        # 步骤1 2: 验证r, s ∈ [1, n-1]
        if not (1 <= r <= self.n-1 and 1 <= s <= self.n-1):
            return False
        
        # 步骤3: 计算ZA 构造M~ = ZA || M
        ZA = self.compute_ZA(ID, public_key)
        M = message.encode('utf-8')
        M_tilde = ZA + M
        
        # 步骤4: 计算e = Hv(M~)
        e_hash = sm3.sm3_hash(list(M_tilde))
        e = int(e_hash, 16) % self.n
        
        # 步骤5: 计算t = (r + s) mod n
        t = (r + s) % self.n
        if t == 0:
            return False
        
        # 步骤6: 计算椭圆曲线点(x1', y1') = [s]G + [t]PA
        sG = self.point_mult(s, (self.Gx, self.Gy))
        tPA = self.point_mult(t, (xA, yA))
        P = self.point_add(sG, tPA)
        if P == 0:
            return False
        x1_prime, y1_prime = P
        
        # 步骤7: 计算R = (e + x1') mod n
        R = (e + x1_prime) % self.n
        
        # 步骤8: 验证R == r
        return R == r



if __name__ == "__main__":
    
    print("SM2数字签名算法".center(80, '='))
    sm2 = SM2()
    # 生成密钥对
    print("\n生成密钥对...")
    private_key = 0x128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263
    public_key = (0x0AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A,
                  0x7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857)
    
    print("=====验证功能=====")
    
    # 显示公钥信息
    print(f"公钥: ({hex(public_key[0])}, {hex(public_key[1])})")
    
    # 要签名的消息
    message = "message digest"
    print(f"\n要签名的消息: '{message}'")
    
    # 生成签名
    print("\n生成签名...")
    k=0x6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F
    signature = sm2.sign_att(message, private_key, public_key,k)
    r, s = signature
    print(f"签名结果: r={hex(r)}, s={hex(s)}")
    
    # 验证签名
    print("\n验证签名...")
    is_valid = sm2.verify(message, signature, public_key)
    
    # 显示验证结果
    print("\n验证结果:")
    if is_valid:
        print("签名验证成功！")
    else:
        print("签名验证失败！")
    
    # 篡改消息测试
    print("\n篡改消息测试...")
    tampered_message = message + "（已篡改）"
    print(f"篡改后的消息: '{tampered_message}'")
    is_valid_tampered = sm2.verify(tampered_message, signature, public_key)
    print(f"验证结果: {'成功' if is_valid_tampered else '失败'} (预期结果: 失败)")
    
    # 篡改签名测试
    print("\n篡改签名测试...")
    tampered_signature = (r, s + 1)  # 修改s值
    is_valid_tampered_sig = sm2.verify(message, tampered_signature, public_key)
    print(f"验证结果: {'成功' if is_valid_tampered_sig else '失败'} (预期结果: 失败)")
    
    
    #k泄露，我们可以手动设定k
    print("\n\n")
    print("=====如果k泄露======")
    k=0x6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F
    # 生成签名
    print("生成签名...")
    signature = sm2.sign_att(message, private_key, public_key,k)
    r, s = signature
    #attacker
    dA=(sm2.mod_inverse((s+r)%sm2.n,sm2.n)*((k-s+sm2.n)%sm2.n))%sm2.n
    print("攻击者的私钥:",hex(dA))
    
    #重用k
    print("\n\n")
    print("=====k重用======")
    k=0x6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F
    # 生成签名
    print("生成签名...")
    signature = sm2.sign_att(message, private_key, public_key,k)
    r1, s1 = signature
    message1="message digest1"
    signature1 = sm2.sign_att(message1, private_key, public_key,k)
    r2, s2 = signature1
    print("签名结果: r=",{hex(r1)}," s=",{hex(s1)})
    print("签名结果: r=",{hex(r2)}," s=",{hex(s2)})
    dA=((s2-s1)%sm2.n)*sm2.mod_inverse((s1-s2+r1-r2+4*sm2.n)%sm2.n,sm2.n)
    dA=dA%sm2.n
    print("私钥为：",hex(dA))
    
    #多个用户使用同样的k
    private_key_Alice=private_key
    public_key_Alice=public_key
    
    private_key_Bob=random.randint(1, sm2.n-1)
    public_key_Bob=sm2.point_mult(private_key_Bob,(sm2.Gx,sm2.Gy))
    print("Alice's key is :\nprivate_key: ",hex(private_key_Alice),"\npublic_key: ",hex(public_key_Alice[0]),", ",hex(public_key_Alice[1]))
    print("Bob's key is :\nprivate_key: ",hex(private_key_Bob),"\npublic_key: ",hex(public_key_Bob[0]),", ",hex(public_key_Bob[1]))
    
    r1,s1=sm2.sign_att(message,private_key_Alice,public_key_Alice,k,"ALICE123@YAHOO.COM")
    r2,s2=sm2.sign_att(message1,private_key_Bob,public_key_Bob,k,"BOB123@YAHOO.COM")
    dB=((k-s2+2*sm2.n)*sm2.mod_inverse((s2+r2+2*sm2.n)%sm2.n,sm2.n))%sm2.n
    print("Alice can deduce Bob secret key:\n",hex(dB))
    
    dA=((k-s1+2*sm2.n)*sm2.mod_inverse((s1+r1+2*sm2.n)%sm2.n,sm2.n))%sm2.n
    print("Bob can deduce Alice secret key:\n",hex(dA))
    
    