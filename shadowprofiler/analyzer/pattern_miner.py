# analyzer/pattern_miner.py

class NoiseRobustMiner:
    def __init__(self, tolerance=5):
        self.tolerance = tolerance

    def _lcs(self, s1, s2):
        m, n = len(s1), len(s2)
        dp = [[0]*(n+1) for _ in range(m+1)]
        for i in range(1, m+1):
            for j in range(1, n+1):
                if abs(abs(s1[i-1]) - abs(s2[j-1])) <= self.tolerance and (s1[i-1]*s2[j-1] > 0):
                    dp[i][j] = dp[i-1][j-1] + 1
                else:
                    dp[i][j] = max(dp[i-1][j], dp[i][j-1])
        res = []; i, j = m, n
        while i > 0 and j > 0:
            if abs(abs(s1[i-1]) - abs(s2[j-1])) <= self.tolerance and (s1[i-1]*s2[j-1] > 0):
                res.append(s1[i-1]); i -= 1; j -= 1
            elif dp[i-1][j] > dp[i][j-1]: i -= 1
            else: j -= 1
        return res[::-1]

    def calculate_confidence(self, skeleton, sequences):
        """
        计算置信度：指纹在所有样本中的平均支持率
        """
        if not skeleton or not sequences: return 0.0
        
        element_supports = []
        for p in skeleton:
            # 统计有多少个原始样本包含这个特定长度和方向的包
            match_count = 0
            for seq in sequences:
                if any(abs(abs(v) - abs(p)) <= self.tolerance and (v*p > 0) for v in seq):
                    match_count += 1
            element_supports.append(match_count / len(sequences))
        
        # 返回平均支持率作为置信度
        return round(sum(element_supports) / len(element_supports), 2)

    def mine_parts(self, sequences):
        if not sequences: return [], [], 0.0
        
        # 1. 挖掘骨架
        skeleton = sequences[0]
        for i in range(1, len(sequences)):
            skeleton = self._lcs(skeleton, sequences[i])
        
        if not skeleton: return [], [], 0.0

        # 2. 自动切分 (根据你的 Lumi 设备数据：连续负数或大负载负数为分界)
        split_idx = len(skeleton) // 2
        for i in range(1, len(skeleton)):
            if skeleton[i] < 0 and abs(skeleton[i]) > 100: 
                split_idx = i
                break
        
        cmd_part = skeleton[:split_idx]
        ent_part = skeleton[split_idx:]
        
        # 3. 计算置信度
        conf = self.calculate_confidence(skeleton, sequences)
        
        return cmd_part, ent_part, conf