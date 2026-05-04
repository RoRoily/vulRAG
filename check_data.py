from collections import Counter
from mmrag.benchmark.dataset import load_jsonl

def main():
    print("正在加载数据集，请稍候...")
    # 1. 加载转换好的 JSONL 数据集
    samples = load_jsonl('./train_data/dataset.jsonl')
    
    # 2. 统计整体的 漏洞(vulnerable) 与 安全(safe) 样本数量
    vuln = [s for s in samples if s.label.value == 'vulnerable']
    safe = [s for s in samples if s.label.value == 'safe']
    
    print("-" * 30)
    print(f"数据集总览:")
    print(f"Total (总计): {len(samples)}")
    print(f"Vulnerable (有漏洞): {len(vuln)}")
    print(f"Safe (安全): {len(safe)}")
    print("-" * 30)
    
    # 3. 统计数据集中具体的 CWE (漏洞类型) 分布情况
    print("CWE 漏洞类型分布:")
    cwe_dist = Counter(s.cwe_id for s in samples if s.cwe_id)
    for cwe, count in cwe_dist.most_common():
        print(f"  {cwe}: {count} 条")
    print("-" * 30)

if __name__ == "__main__":
    main()