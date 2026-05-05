"""
下载所需的基座模型到本地目录。
运行一次即可，后续微调和推理直接使用本地目录。

用法: python save_model.py
"""
from sentence_transformers import SentenceTransformer

print("==================================================")
print("开始下载模型，请确保网络畅通，耐心等待...")
print("==================================================\n")

# --- 1. 下载 CodeFuse-CGE-Small ---
print("正在从 HuggingFace 下载 CodeFuse-CGE-Small 模型...")
print("首次下载约 7-8 GB...")
# 注意：CodeFuse 模型需要 trust_remote_code=True
model_codefuse = SentenceTransformer("codefuse-ai/CodeFuse-CGE-Small", trust_remote_code=True)
model_codefuse.save("./models/codefuse")
print("✅ CodeFuse-CGE-Small 下载完成！已保存到 ./models/codefuse\n")


# --- 2. 下载 UniXcoder ---
print("正在从 HuggingFace 下载 microsoft/unixcoder-base 模型...")
# UniXcoder 是标准的架构，通常不需要 trust_remote_code=True
model_unixcoder = SentenceTransformer("microsoft/unixcoder-base")
model_unixcoder.save("./models/unixcoder")
print("✅ UniXcoder 下载完成！已保存到 ./models/unixcoder\n")

print("==================================================")
print("所有模型下载完毕！")
print("后续微调时使用 --base-model ./models/codefuse 或 ./models/unixcoder 即可。")
print("==================================================")