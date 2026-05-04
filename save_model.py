"""
下载 CodeFuse-CGE-Small 模型到本地目录。
运行一次即可，后续微调和推理直接使用本地目录。

用法: python save_model.py
"""
from sentence_transformers import SentenceTransformer

print("正在从 HuggingFace 下载 CodeFuse-CGE-Small 模型...")
print("首次下载约 7-8 GB，请确保网络畅通，耐心等待。")
print()

model = SentenceTransformer("codefuse-ai/CodeFuse-CGE-Small", trust_remote_code = True)
model.save("./models/codefuse")

print()
print("下载完成！模型已保存到 ./models/codefuse")
print("后续微调时使用 --base-model ./models/codefuse 即可。")
