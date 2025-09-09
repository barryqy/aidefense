#!/usr/bin/env python3
"""
AI Defense Model Validation - Following Official API Documentation
This implements the correct workflow:
1. Setup test model
2. Expose via ngrok
3. Use Management API to register and configure validation
4. Query validation results
"""

import requests
import json
import time
import subprocess
import os
import signal
import sys
from urllib.parse import urlparse

class AIDefenseModelValidator:
    def __init__(self, mgmt_api_key):
        self.mgmt_api_key = mgmt_api_key
        self.mgmt_base_url = "https://api.us.security.cisco.com/api/ai-defense/v1"
        self.model_process = None
        self.ngrok_process = None
        self.ngrok_url = None
        self.model_id = None
        
    def setup_test_model(self):
        """Step 1: Start the vulnerable test model"""
        print("🤖 Step 1: Setting up test model...")
        
        try:
            # Start the mock AI model in background
            self.model_process = subprocess.Popen([
                'python3', 'mock_ai_model.py'
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Wait for model to start
            time.sleep(3)
            
            # Test if model is responding
            response = requests.get("http://localhost:8080/", timeout=5)
            if response.status_code == 200:
                print("✅ Test model running on http://localhost:8080")
                return True
            else:
                print(f"❌ Model not responding: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Failed to start model: {e}")
            return False
    
    def expose_via_ngrok(self):
        """Step 2: Expose model publicly via ngrok"""
        print("🌐 Step 2: Exposing model via ngrok...")
        
        try:
            # Start ngrok to expose port 8080
            self.ngrok_process = subprocess.Popen([
                'ngrok', 'http', '8080', '--log', 'stdout'
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Wait for ngrok to start and get the public URL
            for i in range(30):  # Wait up to 30 seconds
                try:
                    # Query ngrok API for tunnel info
                    ngrok_api = requests.get("http://localhost:4040/api/tunnels", timeout=2)
                    if ngrok_api.status_code == 200:
                        tunnels = ngrok_api.json()['tunnels']
                        for tunnel in tunnels:
                            if tunnel['proto'] == 'https':
                                self.ngrok_url = tunnel['public_url']
                                print(f"✅ Model exposed publicly at: {self.ngrok_url}")
                                return True
                except:
                    pass
                
                time.sleep(1)
            
            print("❌ Failed to get ngrok URL")
            return False
            
        except FileNotFoundError:
            print("❌ ngrok not found. Please install from https://ngrok.com/download")
            return False
        except Exception as e:
            print(f"❌ Failed to start ngrok: {e}")
            return False
    
    def register_model(self):
        """Step 3: Register model with AI Defense Management API"""
        print("📝 Step 3: Registering model with AI Defense...")
        
        headers = {
            'x-cisco-ai-defense-tenant-api-key': self.mgmt_api_key,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        
        model_data = {
            "name": "vulnerable-test-model-v1",
            "description": "Intentionally vulnerable model for validation testing",
            "endpoint": f"{self.ngrok_url}/v1/chat/completions",
            "model_type": "chat-completion",
            "version": "1.0",
            "validation_enabled": True,
            "metadata": {
                "created_by": "ai-defense-lab",
                "purpose": "security_validation_demo",
                "framework": "mock-ai"
            }
        }
        
        try:
            response = requests.post(
                f"{self.mgmt_base_url}/models",
                headers=headers,
                json=model_data,
                timeout=30
            )
            
            if response.status_code == 201:
                result = response.json()
                self.model_id = result.get('id') or result.get('model_id')
                print(f"✅ Model registered successfully")
                print(f"   Model ID: {self.model_id}")
                print(f"   Endpoint: {model_data['endpoint']}")
                return True
            else:
                print(f"❌ Failed to register model: {response.status_code}")
                print(f"   Response: {response.text}")
                return False
                
        except Exception as e:
            print(f"❌ Error registering model: {e}")
            return False
    
    def configure_validation(self):
        """Step 4: Configure and trigger validation"""
        print("🔍 Step 4: Configuring model validation...")
        
        headers = {
            'x-cisco-ai-defense-tenant-api-key': self.mgmt_api_key,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        
        validation_config = {
            "validation_suites": [
                "jailbreak_resistance",
                "harmful_content_prevention", 
                "privacy_protection",
                "system_prompt_protection",
                "role_adherence"
            ],
            "severity_level": "comprehensive",
            "test_intensity": "high",
            "notification_webhook": None,  # Optional webhook for results
            "timeout_minutes": 30
        }
        
        try:
            response = requests.post(
                f"{self.mgmt_base_url}/models/{self.model_id}/validate",
                headers=headers,
                json=validation_config,
                timeout=30
            )
            
            if response.status_code in [200, 202]:
                result = response.json()
                job_id = result.get('job_id') or result.get('validation_id')
                print(f"✅ Validation configured and started")
                print(f"   Job ID: {job_id}")
                print(f"   Status: {result.get('status', 'initiated')}")
                return job_id
            else:
                print(f"❌ Failed to start validation: {response.status_code}")
                print(f"   Response: {response.text}")
                return None
                
        except Exception as e:
            print(f"❌ Error configuring validation: {e}")
            return None
    
    def query_validation_results(self, job_id):
        """Step 5: Query validation results"""
        print("📊 Step 5: Querying validation results...")
        
        headers = {
            'x-cisco-ai-defense-tenant-api-key': self.mgmt_api_key,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        
        max_attempts = 60  # Wait up to 10 minutes
        for attempt in range(max_attempts):
            try:
                # Query validation status
                response = requests.get(
                    f"{self.mgmt_base_url}/validation/jobs/{job_id}",
                    headers=headers,
                    timeout=30
                )
                
                if response.status_code == 200:
                    result = response.json()
                    status = result.get('status')
                    
                    print(f"   Attempt {attempt + 1}: Status = {status}")
                    
                    if status == 'completed':
                        print("✅ Validation completed!")
                        self.display_results(result)
                        return result
                    elif status == 'failed':
                        print("❌ Validation failed!")
                        print(f"   Error: {result.get('error', 'Unknown error')}")
                        return None
                    elif status in ['running', 'pending', 'queued']:
                        if attempt % 10 == 0:  # Show progress every 10 attempts
                            progress = result.get('progress', {})
                            print(f"   Progress: {progress.get('completed', 0)}/{progress.get('total', '?')} tests")
                    
                else:
                    print(f"❌ Error querying results: {response.status_code}")
                
            except Exception as e:
                print(f"   Error: {e}")
            
            time.sleep(10)  # Wait 10 seconds between checks
        
        print("⏰ Validation timed out")
        return None
    
    def display_results(self, results):
        """Display validation results"""
        print("\n" + "="*80)
        print("🛡️  AI DEFENSE MODEL VALIDATION RESULTS")
        print("="*80)
        
        # Overall metrics
        metrics = results.get('metrics', {})
        print(f"Security Score: {metrics.get('security_score', 'N/A')}%")
        print(f"Vulnerabilities Found: {metrics.get('vulnerabilities_found', 0)}")
        print(f"Tests Passed: {metrics.get('tests_passed', 0)}/{metrics.get('total_tests', 0)}")
        print(f"Deployment Recommendation: {results.get('recommendation', 'N/A')}")
        
        # Detailed findings
        findings = results.get('findings', [])
        if findings:
            print(f"\n🚨 SECURITY FINDINGS ({len(findings)} issues):")
            for i, finding in enumerate(findings, 1):
                severity = finding.get('severity', 'UNKNOWN')
                category = finding.get('category', 'Unknown')
                description = finding.get('description', 'No description')
                
                severity_emoji = {
                    'CRITICAL': '🔴',
                    'HIGH': '🟠', 
                    'MEDIUM': '🟡',
                    'LOW': '🟢'
                }.get(severity, '⚪')
                
                print(f"   {i}. {severity_emoji} {severity} - {category}")
                print(f"      {description}")
        
        # Test results by category
        test_results = results.get('test_results', {})
        print(f"\n📋 TEST RESULTS BY CATEGORY:")
        for category, result in test_results.items():
            status = "✅ PASS" if result.get('passed', False) else "❌ FAIL"
            score = result.get('score', 'N/A')
            print(f"   {category}: {status} (Score: {score})")
    
    def cleanup(self):
        """Cleanup processes"""
        print("\n🧹 Cleaning up...")
        
        if self.model_process:
            self.model_process.terminate()
            print("   ✅ Stopped test model")
            
        if self.ngrok_process:
            self.ngrok_process.terminate()
            print("   ✅ Stopped ngrok tunnel")
    
    def run_full_validation(self):
        """Run the complete validation workflow"""
        print("🛡️  AI Defense Model Validation Workflow")
        print("="*80)
        
        try:
            # Step 1: Setup test model
            if not self.setup_test_model():
                return False
            
            # Step 2: Expose via ngrok
            if not self.expose_via_ngrok():
                return False
            
            # Step 3: Register model
            if not self.register_model():
                return False
            
            # Step 4: Configure validation
            job_id = self.configure_validation()
            if not job_id:
                return False
            
            # Step 5: Query results
            results = self.query_validation_results(job_id)
            return results is not None
            
        except KeyboardInterrupt:
            print("\n⏹️  Validation interrupted by user")
            return False
        finally:
            self.cleanup()

def main():
    """Main entry point"""
    # Use the provided lab API key or environment variable
    api_key = os.getenv('AIDEFENSE_MGMT_API_KEY') or "a1de47f520a27c7d655c65303c173f8645d7cb63d8becb88ecffa65e28bb6c2f"
    
    if not api_key:
        print("❌ Please set AIDEFENSE_MGMT_API_KEY environment variable")
        print("   Using default lab API key for testing")
        return
    
    validator = AIDefenseModelValidator(api_key)
    success = validator.run_full_validation()
    
    if success:
        print("\n✅ Model validation completed successfully!")
    else:
        print("\n❌ Model validation failed!")

if __name__ == "__main__":
    main()
