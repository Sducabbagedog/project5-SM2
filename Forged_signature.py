import math
import random
from hashlib import sha256

class ECDSA:
    def __init__(self, a, b, p, G, n):
        """
        初始化椭圆曲线参数
        使用小参数保证演示可运行
        """
        self.a = a
        self.b = b
        self.p = p
        self.G = G
        self.n = n
    
    @staticmethod
    def hash_message(message):
        """哈希函数用于消息摘要"""
        return int(sha256(message.encode()).hexdigest(), 16) % 2**32  # 限制哈希大小为32位
    
    def choose_random_coprime(self):
        """生成与n互质的随机数"""
        while True:
            val = random.randint(2, self.n - 1)
            if math.gcd(val, self.n) == 1:
                return val
    
    def modular_inverse(self, a, m):
        """使用扩展欧几里得算法计算模逆元"""
        g, x, y = self.extended_gcd(a, m)
        if g != 1:
            return None  # 逆元不存在
        return x % m
    
    def extended_gcd(self, a, b):
        """扩展欧几里得算法"""
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = self.extended_gcd(b % a, a)
            return (g, x - (b // a) * y, y)
    
    def point_add(self, P, Q):
        """椭圆曲线点加运算，正确处理无穷远点"""
        if P == "O":
            return Q
        if Q == "O":
            return P
        
        x_p, y_p = P
        x_q, y_q = Q
        
        if P != Q:
            # 计算斜率
            denominator = (x_p - x_q) % self.p
            inv_denominator = self.modular_inverse(denominator, self.p)
            if inv_denominator is None:
                return "O"  # 点相加结果为无穷远点
            k = ((y_p - y_q) * inv_denominator) % self.p
        else:
            # 点加倍
            denominator = (2 * y_p) % self.p
            inv_denominator = self.modular_inverse(denominator, self.p)
            if inv_denominator is None:
                return "O"
            k = ((3 * x_p * x_p + self.a) * inv_denominator) % self.p
        
        x_r = (k * k - x_p - x_q) % self.p
        y_r = (k * (x_p - x_r) - y_p) % self.p
        
        return (x_r, y_r)
    
    def scalar_multiply(self, k, P):
        """使用快速幂算法实现标量乘法"""
        result = "O"  # 无穷远点
        current = P
        
        while k > 0:
            if k % 2 == 1:
                result = self.point_add(result, current)
            current = self.point_add(current, current)  # 点加倍
            k = k // 2
        
        return result
    
    def generate_key_pair(self):
        """生成密钥对"""
        d = random.randint(1, self.n - 1)  # 私钥
        Q = self.scalar_multiply(d, self.G)  # 公钥
        return d, Q
    
    def sign(self, message, private_key, k=None):
        """ECDSA签名"""
        if k is None:
            k = self.choose_random_coprime()
        
        R = self.scalar_multiply(k, self.G)
        if R == "O":
            return self.sign(message, private_key)  # 重新选择k
        
        r = R[0] % self.n
        e = self.hash_message(message) % self.n
        s = (self.modular_inverse(k, self.n) * (e + private_key * r)) % self.n
        
        return (r, s)
    
    def verify(self, message, signature, public_key):
        """ECDSA验证"""
        r, s = signature
        if not (1 <= r < self.n and 1 <= s < self.n):
            return False
        
        e = self.hash_message(message) % self.n
        w = self.modular_inverse(s, self.n)
        if w is None:
            return False
        
        u1 = (e * w) % self.n
        u2 = (r * w) % self.n
        
        P1 = self.scalar_multiply(u1, self.G)
        P2 = self.scalar_multiply(u2, public_key)
        R = self.point_add(P1, P2)
        
        if R == "O":
            return False
        
        return R[0] % self.n == r
    
    def forge_signature(self, public_key):
        """伪造签名(无消息攻击) - 使用小参数保证可运行"""
        # 限制参数大小以保证运行时间
        max_attempts = 10
        for _ in range(max_attempts):
            u = random.randint(1, min(self.n, 1000))
            v = random.randint(1, min(self.n, 1000))
            
            # 确保u和v与n互质
            if math.gcd(u, self.n) != 1 or math.gcd(v, self.n) != 1:
                continue
            
            # 计算 R = u*G + v*Q
            uG = self.scalar_multiply(u, self.G)
            vQ = self.scalar_multiply(v, public_key)
            R = self.point_add(uG, vQ)
            
            if R == "O":
                continue
            
            r = R[0] % self.n
            v_inv = self.modular_inverse(v, self.n)
            if v_inv is None:
                continue
                
            e = (r * u * v_inv) % self.n
            s = (r * v_inv) % self.n
            
            # 验证伪造的签名
            if self.verify_forged_signature(e, r, s, public_key):
                return (e, r, s), True
        
        return None, False
    
    def verify_forged_signature(self, e, r, s, public_key):
        """验证伪造的签名"""
        if not (1 <= r < self.n and 1 <= s < self.n):
            return False
        
        w = self.modular_inverse(s, self.n)
        if w is None:
            return False
        
        u1 = (e * w) % self.n
        u2 = (r * w) % self.n
        
        P1 = self.scalar_multiply(u1, self.G)
        P2 = self.scalar_multiply(u2, public_key)
        R = self.point_add(P1, P2)
        
        if R == "O":
            return False
        
        return R[0] % self.n == r


# 使用小参数测试
if __name__ == "__main__":
    # 测试参数(小参数保证可运行)
    a = 2
    b = 2
    p = 17  # 小质数
    G = (5, 1)  # 基点
    n = 19  # 阶数
    
    # 初始化ECDSA
    ecdsa = ECDSA(a, b, p, G, n)
    
    print("=== 正常签名验证流程 ===")
    private_key, public_key = ecdsa.generate_key_pair()
    print(f"私钥: {private_key}, 公钥: {public_key}")
    
    message = "Test message"
    signature = ecdsa.sign(message, private_key)
    print(f"签名: {signature}")
    print(f"验证结果: {ecdsa.verify(message, signature, public_key)}")
    
    print("\n=== 伪造签名攻击演示 ===")
    forged_data, is_valid = ecdsa.forge_signature(public_key)
    if forged_data:
        e, r, s = forged_data
        print(f"伪造的签名数据: e={e}, r={r}, s={s}")
        print(f"验证伪造签名的结果: {is_valid}")
    else:
        print("伪造签名失败(可能参数选择不当)")
        

