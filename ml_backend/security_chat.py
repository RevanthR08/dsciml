import os
from ai_intelligence import SecurityAI

def main():
    ai = SecurityAI()
    print("\n" + "="*60)
    print(" 🛡️  LOG-AI INTERACTIVE SECURITY CHAT")
    print(" (Type 'exit' or 'quit' to stop)")
    print("="*60)
    
    while True:
        question = input("\n👤 You: ")
        if question.lower() in ['exit', 'quit', 'q']:
            print("👋 Closing Security Chat...")
            break
            
        if not question.strip():
            continue
            
        print("\n🤖 AI is analyzing the forensic data...")
        answer = ai.answer_question(question)
        
        print(f"\n📢 AI Answer:\n{'-'*20}\n{answer}\n{'-'*20}")

if __name__ == "__main__":
    main()
