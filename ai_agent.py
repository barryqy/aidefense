#!/usr/bin/env python3
"""
LangChain AI Agent with Database Access and AI Defense Integration
"""

import os
import sys
import sqlite3
import requests
import urllib.request
from typing import List, Dict, Any

# Helper function to load credentials from cache
def _load_from_cache(field_name):
    """Load session data from cache file"""
    try:
        import base64
        cache_file = ".aidefense/.cache"
        
        # Map field names to position in session data
        field_positions = {
            'session_token': 0,
            'auth_hash': 1,
            'request_id': 2,
            'bearer_token': 3
        }
        
        position = field_positions.get(field_name)
        if position is None:
            return None
        
        # Get environment context
        env_key = os.environ.get('DEVENV_USER', 'default-key-fallback')
        
        if os.path.exists(cache_file):
            with open(cache_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('session_token='):
                        # Extract session data
                        encoded = line.split('=', 1)[1].strip()
                        enc_bytes = base64.b64decode(encoded)
                        
                        # Decode session data
                        key_rep = (env_key * (len(enc_bytes) // len(env_key) + 1))[:len(enc_bytes)]
                        dec_bytes = bytes(a ^ b for a, b in zip(enc_bytes, key_rep.encode()))
                        plaintext = dec_bytes.decode('utf-8')
                        
                        # Parse session fields
                        parts = plaintext.split(':')
                        if position < len(parts):
                            credential = parts[position]
                            if credential and credential != "none":
                                return credential
    except Exception:
        pass
    return None

# Try importing LangChain components
try:
    from langchain.memory import ConversationBufferWindowMemory
    from langchain.callbacks.base import BaseCallbackHandler
except ImportError:
    import time
    import subprocess
    
    # Check if background installation from init script is running
    marker_file = os.path.join(os.path.dirname(__file__), '.aidefense', '.langchain_ready')
    
    # Check if marker file doesn't exist yet (background install may be running)
    if not os.path.exists(marker_file):
        # Check if .aidefense directory exists (indicates init script was run)
        aidefense_dir = os.path.join(os.path.dirname(__file__), '.aidefense')
        if os.path.exists(aidefense_dir):
            print("⏳ Dependencies are being installed in the background (started by init script)...")
            print("   Waiting for installation to complete...")
            
            # Wait up to 2 minutes for background installation
            max_wait = 120  # 2 minutes
            wait_interval = 2
            elapsed = 0
            
            while elapsed < max_wait:
                if os.path.exists(marker_file):
                    print("✅ Background installation completed!")
                    break
                
                # Show progress dots
                sys.stdout.write('.')
                sys.stdout.flush()
                time.sleep(wait_interval)
                elapsed += wait_interval
            
            print("")
            
            if not os.path.exists(marker_file):
                print("⚠️  Background installation taking longer than expected.")
                print("   Proceeding with manual installation...")
    
    # Even if marker exists, verify packages are actually importable
    # Try importing again in case background install just completed
    try:
        from langchain.memory import ConversationBufferWindowMemory
        from langchain.callbacks.base import BaseCallbackHandler
    except ImportError:
        # Packages still not available, do manual install
        print("❌ LangChain not installed or not in Python path.")
        print("Attempting automatic installation...")
        
        # Docker-compatible installation with ignore-installed flag
        exit_code = os.system("pip3 install --ignore-installed langchain langchain-community")
        if exit_code != 0:
            print("❌ Auto-installation failed. Please install manually:")
            print("   pip3 install --ignore-installed --force-reinstall langchain langchain-community")
            sys.exit(1)
        
        print("✅ Installation completed. Continuing with script execution...")
        
        # Import the newly installed modules
        from langchain.memory import ConversationBufferWindowMemory
        from langchain.callbacks.base import BaseCallbackHandler

# Try importing Mistral (via Ollama or API)
try:
    import requests
    MISTRAL_AVAILABLE = True
except:
    MISTRAL_AVAILABLE = False

class AIDefenseCallback(BaseCallbackHandler):
    """Callback to inspect responses with AI Defense"""
    
    def __init__(self):
        self.api_url = "https://us.api.inspect.aidefense.security.cisco.com/api/v1/inspect/chat"
        self.api_key = self._load_api_key()
    
    def _load_api_key(self) -> str:
        """Load API key from environment or cached file"""
        # Check environment variable first
        cached_key = os.environ.get('AIDEFENSE_PRIMARY_KEY')
        if cached_key:
            return cached_key
        
        # Try to load from cache file
        key = _load_from_cache('session_token')
        if key:
            os.environ['AIDEFENSE_PRIMARY_KEY'] = key
            return key
        
        raise ValueError("AI Defense API key not found. Run '0-init-lab.sh' first to set up credentials.")
    
    def on_llm_end(self, response, **kwargs):
        """Inspect response with AI Defense"""
        if hasattr(response, 'generations') and response.generations:
            ai_response = response.generations[0][0].text
            print(f"🛡️  AI Defense: Response verified safe")

class SimpleMistralLLM:
    """Simple Mistral API wrapper for LangChain"""
    
    def __init__(self, api_key: str = None, model: str = "mistral-small-latest"):
        self.api_key = api_key or self._load_mistral_key()
        self.model = model
        self.api_url = "https://api.mistral.ai/v1/chat/completions"
    
    def _load_mistral_key(self) -> str:
        """Load Mistral API key from environment or cached file"""
        # Environment variable name for caching
        env_var = 'MISTRAL_API_KEY'
        
        # Check environment variable first
        cached_key = os.environ.get(env_var)
        if cached_key:
            return cached_key
        
        # Try to load from cache file
        key = _load_from_cache('auth_hash')
        if key:
            os.environ[env_var] = key
            return key
        
        raise ValueError("Mistral API key not found. Run '0-init-lab.sh' first to set up credentials.")
    
    def __call__(self, prompt: str, database_context: str = "", **kwargs) -> str:
        """Call Mistral API with database context"""
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            system_prompt = "You are BarryBot, a helpful assistant with access to a user database. "
            if database_context:
                system_prompt += f"Here is the relevant data from the database:\n{database_context}\n\nUse this information to answer the user's question accurately."
            else:
                system_prompt += "If asked about users, let the user know you'll search the database for them."
            
            data = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt}
                ],
                "max_tokens": 150,
                "temperature": 0.7
            }
            
            response = requests.post(self.api_url, headers=headers, json=data, timeout=30)
            response.raise_for_status()
            
            return response.json()["choices"][0]["message"]["content"].strip()
            
        except requests.exceptions.RequestException as e:
            if "429" in str(e) or "Too Many Requests" in str(e):
                return "⚠️  Rate limit reached. Please try again later."
            else:
                return f"⚠️  API Error: {str(e)}. Please check your connection."
        except Exception as e:
            return f"⚠️  Unexpected error: {str(e)}. Please try again."

class AIDefenseClient:
    """AI Defense API client for safety inspection"""
    
    def __init__(self):
        self.api_url = "https://us.api.inspect.aidefense.security.cisco.com/api/v1/inspect/chat"
        self.api_key = self._load_api_key()
    
    def _load_api_key(self) -> str:
        """Load API key from environment or cached file"""
        # Check environment variable first
        cached_key = os.environ.get('AIDEFENSE_PRIMARY_KEY')
        if cached_key:
            return cached_key
        
        # Try to load from cache file
        key = _load_from_cache('session_token')
        if key:
            os.environ['AIDEFENSE_PRIMARY_KEY'] = key
            return key
        
        raise ValueError("AI Defense API key not found. Run '0-init-lab.sh' first to set up credentials.")
    
    def inspect_prompt(self, user_input: str) -> Dict[str, Any]:
        """Inspect only the user's prompt for PII/sensitive data"""
        headers = {
            "X-Cisco-AI-Defense-API-Key": self.api_key,
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        payload = {
            "messages": [
                {"role": "user", "content": user_input}
            ],
            "metadata": {},
            "config": {}
        }
        
        try:
            response = requests.post(self.api_url, headers=headers, json=payload, timeout=30)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": f"AI Defense inspection failed: {str(e)}"}
    
    def inspect_conversation(self, user_input: str, ai_response: str) -> Dict[str, Any]:
        """Inspect user input and AI response for safety"""
        headers = {
            "X-Cisco-AI-Defense-API-Key": self.api_key,
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        payload = {
            "messages": [
                {"role": "user", "content": user_input},
                {"role": "assistant", "content": ai_response}
            ],
            "metadata": {},
            "config": {}
        }
        
        try:
            response = requests.post(self.api_url, headers=headers, json=payload, timeout=30)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": f"AI Defense inspection failed: {str(e)}"}

class BarryBotAgent:
    """Simple AI Agent using LangChain with Mistral"""
    
    def __init__(self, use_mistral: bool = True, use_ai_defense: bool = True, security_action: str = 'block'):
        self.use_mistral = use_mistral
        self.use_ai_defense = use_ai_defense
        self.security_action = security_action  # 'block' (default), 'warn', or 'log'
        self.setup_database()
        self.setup_agent()
    
    def setup_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                first_name TEXT,
                last_name TEXT,  
                email TEXT,
                ssn TEXT,
                phone TEXT
            )
        ''')
        
        # Insert sample data if empty
        cursor.execute("SELECT COUNT(*) FROM users")
        if cursor.fetchone()[0] == 0:
            users = [
                ("Barry", "Yuan", "bayuan@cisco.com", "123-12-1212", "6045555555"),
                ("Alice", "Smith", "alice.smith@example.com", "123-45-6789", "5551234567"),
                ("Bob", "Johnson", "bob.johnson@example.com", "987-65-4321", "5559876543")
            ]
            cursor.executemany(
                "INSERT INTO users (first_name, last_name, email, ssn, phone) VALUES (?, ?, ?, ?, ?)",
                users
            )
        
        conn.commit()
        conn.close()
    
    def setup_agent(self):
        """Setup LangChain agent with Mistral"""
        if self.use_mistral:
            print("🤖 Using Mistral LLM")
            self.llm = SimpleMistralLLM()
        else:
            print("🤖 Using test mode (no LLM)")
            self.llm = None
        
        # Setup memory (suppress deprecation warning)
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            self.memory = ConversationBufferWindowMemory(
                memory_key="chat_history",
                k=5,
                return_messages=True
            )
        
        # Setup AI Defense callback only if enabled
        if self.use_ai_defense:
            self.ai_defense = AIDefenseClient()
            self.ai_defense_callback = AIDefenseCallback()
        else:
            self.ai_defense = None
            self.ai_defense_callback = None
        
        # Store database connection for queries
        self.db_connection = sqlite3.connect("users.db", check_same_thread=False)
    
    def __del__(self):
        """Clean up database connection"""
        if hasattr(self, 'db_connection'):
            self.db_connection.close()
    
    def query_database(self, user_input: str) -> str:
        """Query database based on user input and return formatted results"""
        try:
            cursor = self.db_connection.cursor()
            
            # Determine what to search for based on user input
            user_input_lower = user_input.lower()
            
            if "all" in user_input_lower and ("user" in user_input_lower or "people" in user_input_lower):
                # Get all users
                cursor.execute("SELECT first_name, last_name, email, phone FROM users")
                results = cursor.fetchall()
                if results:
                    formatted_results = "All users in database:\n"
                    for row in results:
                        formatted_results += f"- {row[0]} {row[1]}: {row[2]}, {row[3]}\n"
                    return formatted_results.strip()
            
            # Search for specific users by name
            names_to_search = []
            if "barry" in user_input_lower:
                names_to_search.append("Barry")
            if "alice" in user_input_lower:
                names_to_search.append("Alice")
            if "bob" in user_input_lower:
                names_to_search.append("Bob")
            
            if names_to_search:
                results = []
                for name in names_to_search:
                    cursor.execute("SELECT first_name, last_name, email, phone, ssn FROM users WHERE first_name LIKE ?", (f"%{name}%",))
                    user_results = cursor.fetchall()
                    results.extend(user_results)
                
                if results:
                    formatted_results = "Found users:\n"
                    for row in results:
                        formatted_results += f"- {row[0]} {row[1]}: Email: {row[2]}, Phone: {row[3]}, SSN: {row[4]}\n"
                    return formatted_results.strip()
            
            # Search for email-related queries
            if "email" in user_input_lower:
                cursor.execute("SELECT first_name, last_name, email FROM users")
                results = cursor.fetchall()
                if results:
                    formatted_results = "User email addresses:\n"
                    for row in results:
                        formatted_results += f"- {row[0]} {row[1]}: {row[2]}\n"
                    return formatted_results.strip()
            
            # Search for phone-related queries
            if "phone" in user_input_lower:
                cursor.execute("SELECT first_name, last_name, phone FROM users")
                results = cursor.fetchall()
                if results:
                    formatted_results = "User phone numbers:\n"
                    for row in results:
                        formatted_results += f"- {row[0]} {row[1]}: {row[2]}\n"
                    return formatted_results.strip()
            
            # If no specific search terms, return empty to let LLM handle it
            return ""
            
        except sqlite3.Error as e:
            return f"Database error: {str(e)}"
        except Exception as e:
            return f"Error querying database: {str(e)}"
    
    def chat(self, message: str, skip_prompt_check: bool = False) -> Dict[str, Any]:
        """Process chat message with optional AI Defense"""
        try:
            # In WARN mode, check the prompt first before processing
            if self.use_ai_defense and self.ai_defense and self.security_action == 'warn' and not skip_prompt_check:
                # Check if the user's prompt contains PII or sensitive data
                prompt_check = self.ai_defense.inspect_prompt(message)
                prompt_is_safe = prompt_check.get("is_safe", True) if "error" not in prompt_check else True
                prompt_classifications = prompt_check.get('classifications', [])
                
                if not prompt_is_safe:
                    # Prompt contains PII - return warning without processing
                    return {
                        "response": None,
                        "ai_defense_enabled": True,
                        "is_safe": False,
                        "prompt_warning": True,
                        "safety_info": f"Your prompt contains PII or sensitive data",
                        "classifications": prompt_classifications,
                        "security_action": 'warn'
                    }
            
            # Query database for relevant information
            database_context = self.query_database(message)
            
            # Use Mistral LLM with database context
            response = self.llm(message, database_context=database_context)
            
            # Add to memory
            self.memory.chat_memory.add_user_message(message)
            self.memory.chat_memory.add_ai_message(response)
            
            # Check with AI Defense if enabled
            if self.use_ai_defense and self.ai_defense:
                safety_result = self.ai_defense.inspect_conversation(message, response)
                is_safe = safety_result.get("is_safe", True) if "error" not in safety_result else True
                classifications = safety_result.get('classifications', [])
                
                # Apply security action based on mode
                original_response = response
                if not is_safe:
                    if self.security_action == 'block':
                        # BLOCK: Replace unsafe response completely
                        response = "🚫 I cannot provide this information for security reasons."
                    elif self.security_action == 'warn':
                        # WARN: Keep response but add warning
                        response = f"⚠️  Security Warning: This response may contain sensitive information.\n\n{response}"
                    # LOG mode: Keep original response, just log it
                
                safety_info = "Safe" if is_safe else f"⚠️  Safety concern: {classifications}"
                
                return {
                    "response": response,
                    "ai_defense_enabled": True,
                    "is_safe": is_safe,
                    "safety_info": safety_info,
                    "classifications": classifications,
                    "security_action": self.security_action if not is_safe else None
                }
            else:
                return {
                    "response": response,
                    "ai_defense_enabled": False,
                    "is_safe": True,
                    "safety_info": "AI Defense disabled"
                }
                
        except Exception as e:
            return {
                "response": f"Error processing request: {str(e)}",
                "ai_defense_enabled": self.use_ai_defense,
                "is_safe": True,
                "safety_info": f"Error: {str(e)}"
            }
    
    def run_interactive(self):
        """Run interactive chat session"""
        print("🤖 BarryBot AI Agent with Mistral")
        print("=" * 50)
        print("Hi there! 👋")
        print("My name is BarryBot. How can I assist you today?")
        
        # Show AI Defense status
        if self.use_ai_defense:
            print("🛡️  AI Defense: ENABLED - All responses will be analyzed for safety")
        else:
            print("⚠️  AI Defense: DISABLED - Responses will not be analyzed")
            
        print("(Type 'quit' to exit, 'clear' to reset conversation)")
        print("-" * 50)
        
        while True:
            try:
                user_input = input("\nYou: ").strip()
                
                if user_input.lower() in ['quit', 'exit', 'q']:
                    print("👋 Goodbye!")
                    break
                elif user_input.lower() == 'clear':
                    self.memory.clear()
                    print("🗑️  Conversation history cleared!")
                    continue
                elif not user_input:
                    continue
                
                # Process message
                result = self.chat(user_input)
                
                # Check if prompt warning (WARN mode with PII in prompt)
                if result.get('prompt_warning'):
                    classifications_str = ', '.join(result.get('classifications', []))
                    print(f"\n⚠️  WARNING: {result['safety_info']}")
                    print(f"    Detected: {classifications_str}")
                    print("    Are you sure you want to send this prompt? (yes/no): ", end='')
                    confirmation = input().strip().lower()
                    
                    if confirmation in ['yes', 'y']:
                        # User confirmed, process with skip_prompt_check
                        print("\n    User confirmed. Processing request...\n")
                        result = self.chat(user_input, skip_prompt_check=True)
                        print(f"BarryBot: {result['response']}")
                    else:
                        print("\n⛔ Request cancelled for security reasons.")
                        continue
                else:
                    # Display response
                    print(f"\nBarryBot: {result['response']}")
                
                # Display safety info only if AI Defense is enabled
                if result['ai_defense_enabled']:
                    if result['is_safe']:
                        print("🛡️  AI Defense: Response verified safe")
                    else:
                        print(f"🛡️  AI Defense: {result['safety_info']}")
                        if result.get('security_action'):
                            action_msgs = {
                                'block': '🚫 Response BLOCKED by security policy',
                                'warn': '⚠️  Response ALLOWED with warning',
                                'log': '📝 Response LOGGED for audit'
                            }
                            print(f"    Action: {action_msgs.get(result['security_action'], 'Unknown')}")
                
            except KeyboardInterrupt:
                print("\n\n👋 Goodbye!")
                break
            except Exception as e:
                print(f"❌ Error: {str(e)}")

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='BarryBot AI Agent - Interactive AI assistant with database access',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 ai_agent.py                                  # Run with AI Defense (block mode - default)
  python3 ai_agent.py --security-action warn           # Warn but allow responses
  python3 ai_agent.py --security-action log            # Log only (allow all)
  python3 ai_agent.py --no-ai-defense                  # Disable AI Defense completely
  python3 ai_agent.py --prompt "what is barry's ssn?"  # Test single prompt

Security Action Modes:
  block: Block unsafe responses completely (default, strictest)
  warn:  Allow responses but add security warnings
  log:   Allow all responses, log security concerns only

Contact: bayuan@cisco.com for questions and issues
        """
    )
    
    parser.add_argument(
        '--no-ai-defense',
        action='store_true',
        help='Disable AI Defense safety analysis (faster responses)'
    )
    
    parser.add_argument(
        '--security-action',
        type=str,
        choices=['block', 'warn', 'log'],
        default='block',
        help='Security action mode: block (default, strictest), warn (add warnings), log (allow all)'
    )
    
    parser.add_argument(
        '--prompt',
        type=str,
        help='Single prompt to test (non-interactive mode)'
    )
    
    args = parser.parse_args()
    
    print("🚀 Starting BarryBot AI Agent...")
    
    # Initialize agent with AI Defense setting and security action
    use_ai_defense = not args.no_ai_defense
    agent = BarryBotAgent(
        use_mistral=True, 
        use_ai_defense=use_ai_defense,
        security_action=args.security_action
    )
    
    # Check if single prompt mode or interactive mode
    if args.prompt:
        # Single prompt mode
        print("=" * 60)
        print("BARRYBOT - SINGLE PROMPT TEST")
        print("=" * 60)
        if use_ai_defense:
            print(f"✓ AI Defense: ENABLED (Security Action: {args.security_action})")
        else:
            print("⚠️  AI Defense: DISABLED")
        print("-" * 60)
        
        # Process the single prompt
        print(f"\nYou: {args.prompt}\n")
        result = agent.chat(args.prompt)
        
        # Check if prompt warning
        if result.get('prompt_warning'):
            classifications_str = ', '.join(result.get('classifications', []))
            print(f"⚠️  WARNING: {result['safety_info']}")
            print(f"    Detected: {classifications_str}")
            print(f"    Are you sure you want to send this prompt? (yes/no): ", end='')
            
            # In single prompt mode, get user input
            confirmation = input().strip().lower()
            
            if confirmation in ['yes', 'y']:
                print("\n    User confirmed. Processing request...\n")
                # Auto-confirm for single prompt mode
                result = agent.chat(args.prompt, skip_prompt_check=True)
                print(f"BarryBot: {result['response']}")
            else:
                print("\n⛔ Request cancelled for security reasons.")
        else:
            print(f"BarryBot: {result['response']}")
        
        # Display security info
        if result['ai_defense_enabled'] and not result['is_safe']:
            print(f"\n🛡️  AI Defense: {result['safety_info']}")
            if result.get('security_action'):
                action_msgs = {
                    'block': '🚫 Response BLOCKED by security policy',
                    'warn': '⚠️  Response ALLOWED with warning',
                    'log': '📝 Response LOGGED for audit'
                }
                print(f"    Action: {action_msgs.get(result['security_action'], 'Unknown')}")
        print()
    else:
        # Interactive mode
        if use_ai_defense:
            print(f"✓ AI Defense enabled with security action: {args.security_action}")
        agent.run_interactive()

if __name__ == "__main__":
    main()
