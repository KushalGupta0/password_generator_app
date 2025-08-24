"""
Password Generator Core Logic
Advanced password generation with customizable complexity and security features
"""

import secrets
import random
import string
import logging
from typing import Dict, List, Optional, Tuple, Set
from datetime import datetime
import math

from app_config import (
    CHARACTER_SETS,
    DEFAULT_COMPLEXITY,
    MIN_PASSWORD_LENGTH,
    MAX_PASSWORD_LENGTH,
    DEFAULT_PASSWORD_LENGTH
)
from security import validate_password_strength, crypto_manager


class PasswordGenerator:
    """Advanced password generator with comprehensive security features"""
    
    def __init__(self):
        """Initialize password generator with default settings"""
        self.logger = logging.getLogger(__name__)
        self.character_sets = CHARACTER_SETS.copy()
        self.generation_stats = {
            'total_generated': 0,
            'last_generation': None,
            'average_strength': 0.0
        }
        
        # Extended character sets for more options
        self.extended_sets = {
            'ambiguous': 'il1Lo0O',  # Characters to potentially exclude
            'similar': 'il1Lo0O',    # Visually similar characters
            'brackets': '[]{}()',     # Bracket characters
            'quotes': '\'"``',        # Quote characters
            'math': '+-*/=<>',        # Mathematical operators
            'currency': '$€£¥₹',      # Currency symbols
        }
        
        # Common weak patterns to avoid
        self.weak_patterns = [
            'password', '123456', 'qwerty', 'admin', 'login',
            'abc', '111', '000', 'aaa', 'zzz', '123', '321'
        ]
    
    def generate_password(self, 
                         length: int = DEFAULT_PASSWORD_LENGTH,
                         complexity: Dict[str, bool] = None,
                         exclude_ambiguous: bool = False,
                         exclude_similar: bool = False,
                         custom_rules: Dict[str, any] = None) -> Dict[str, any]:
        """
        Generate a secure password with specified requirements
        
        Args:
            length: Password length (4-128 characters)
            complexity: Dict specifying character types to include
            exclude_ambiguous: Remove visually ambiguous characters
            exclude_similar: Remove visually similar characters  
            custom_rules: Additional generation rules
            
        Returns:
            Dict containing password and metadata
        """
        try:
            # Validate input parameters
            validation_result = self._validate_generation_params(length, complexity, custom_rules)
            if not validation_result['is_valid']:
                return {
                    'success': False,
                    'error': validation_result['error'],
                    'password': None
                }
            
            # Use default complexity if not provided
            if complexity is None:
                complexity = DEFAULT_COMPLEXITY.copy()
            
            # Apply custom rules
            if custom_rules:
                complexity.update(custom_rules.get('complexity_override', {}))
            
            # Build character pool
            char_pool = self._build_character_pool(
                complexity, exclude_ambiguous, exclude_similar, custom_rules
            )
            
            if not char_pool['pool']:
                return {
                    'success': False,
                    'error': 'No valid characters available for password generation',
                    'password': None
                }
            
            # Generate password with multiple attempts for quality
            best_password = None
            best_score = 0
            max_attempts = 10
            
            for attempt in range(max_attempts):
                candidate = self._generate_password_candidate(
                    length, char_pool, complexity, custom_rules
                )
                
                # Evaluate password quality
                quality_score = self._evaluate_password_quality(candidate, custom_rules)
                
                if quality_score > best_score:
                    best_password = candidate
                    best_score = quality_score
                
                # If we got a high-quality password, use it
                if quality_score >= 85:
                    break
            
            if not best_password:
                return {
                    'success': False,
                    'error': 'Failed to generate satisfactory password',
                    'password': None
                }
            
            # Calculate comprehensive metadata
            metadata = self._generate_password_metadata(best_password, complexity, char_pool)
            
            # Update statistics
            self._update_generation_stats(metadata)
            
            self.logger.info(f"Password generated: length={length}, strength={metadata['strength_analysis']['strength']}")
            
            return {
                'success': True,
                'password': best_password,
                'length': len(best_password),
                'complexity_used': complexity,
                'metadata': metadata,
                'generation_time': datetime.now().isoformat()
            }
        
        except Exception as e:
            self.logger.error(f"Password generation failed: {e}")
            return {
                'success': False,
                'error': f'Generation error: {str(e)}',
                'password': None
            }
    
    def _validate_generation_params(self, length: int, complexity: Dict, custom_rules: Dict) -> Dict[str, any]:
        """Validate password generation parameters"""
        errors = []
        
        # Length validation
        if not isinstance(length, int):
            errors.append("Length must be an integer")
        elif length < MIN_PASSWORD_LENGTH:
            errors.append(f"Length must be at least {MIN_PASSWORD_LENGTH}")
        elif length > MAX_PASSWORD_LENGTH:
            errors.append(f"Length cannot exceed {MAX_PASSWORD_LENGTH}")
        
        # Complexity validation
        if complexity and not isinstance(complexity, dict):
            errors.append("Complexity must be a dictionary")
        elif complexity:
            valid_keys = set(self.character_sets.keys())
            invalid_keys = set(complexity.keys()) - valid_keys
            if invalid_keys:
                errors.append(f"Invalid complexity keys: {invalid_keys}")
        
        # Custom rules validation
        if custom_rules and not isinstance(custom_rules, dict):
            errors.append("Custom rules must be a dictionary")
        
        return {
            'is_valid': len(errors) == 0,
            'error': '; '.join(errors) if errors else None
        }
    
    def _build_character_pool(self, complexity: Dict[str, bool], 
                            exclude_ambiguous: bool, exclude_similar: bool,
                            custom_rules: Dict = None) -> Dict[str, any]:
        """Build character pool based on complexity requirements"""
        pool = ""
        used_sets = []
        
        # Add character sets based on complexity
        for char_type, include in complexity.items():
            if include and char_type in self.character_sets:
                chars = self.character_sets[char_type]
                pool += chars
                used_sets.append(char_type)
        
        # Add custom character sets if specified
        if custom_rules and 'additional_chars' in custom_rules:
            pool += custom_rules['additional_chars']
            used_sets.append('custom')
        
        # Remove excluded characters
        if exclude_ambiguous:
            for char in self.extended_sets['ambiguous']:
                pool = pool.replace(char, '')
        
        if exclude_similar:
            for char in self.extended_sets['similar']:
                pool = pool.replace(char, '')
        
        # Remove custom excluded characters
        if custom_rules and 'exclude_chars' in custom_rules:
            for char in custom_rules['exclude_chars']:
                pool = pool.replace(char, '')
        
        # Remove duplicates while preserving randomness
        pool = ''.join(sorted(set(pool)))
        
        return {
            'pool': pool,
            'used_sets': used_sets,
            'pool_size': len(pool),
            'excluded_ambiguous': exclude_ambiguous,
            'excluded_similar': exclude_similar
        }
    
    def _generate_password_candidate(self, length: int, char_pool: Dict, 
                                   complexity: Dict, custom_rules: Dict = None) -> str:
        """Generate a single password candidate"""
        password = []
        pool = char_pool['pool']
        
        # Ensure at least one character from each required set
        required_chars = []
        for char_type, include in complexity.items():
            if include and char_type in self.character_sets:
                char_set = self.character_sets[char_type]
                # Filter out excluded characters
                filtered_set = ''.join(c for c in char_set if c in pool)
                if filtered_set:
                    required_chars.append(secrets.choice(filtered_set))
        
        # Add required characters
        password.extend(required_chars)
        
        # Fill remaining positions with random characters
        remaining_length = length - len(required_chars)
        for _ in range(remaining_length):
            password.append(secrets.choice(pool))
        
        # Shuffle to avoid predictable patterns
        secrets.SystemRandom().shuffle(password)
        
        generated_password = ''.join(password)
        
        # Apply post-generation rules
        if custom_rules:
            generated_password = self._apply_custom_rules(generated_password, custom_rules)
        
        return generated_password
    
    def _apply_custom_rules(self, password: str, custom_rules: Dict) -> str:
        """Apply custom post-generation rules"""
        # Avoid consecutive identical characters
        if custom_rules.get('no_consecutive_identical', False):
            password = self._avoid_consecutive_chars(password)
        
        # Ensure minimum character type requirements
        if 'min_char_types' in custom_rules:
            password = self._ensure_min_char_types(password, custom_rules['min_char_types'])
        
        # Apply pattern avoidance
        if custom_rules.get('avoid_common_patterns', True):
            password = self._avoid_weak_patterns(password)
        
        return password
    
    def _avoid_consecutive_chars(self, password: str, max_consecutive: int = 2) -> str:
        """Remove excessive consecutive identical characters"""
        if len(password) <= max_consecutive:
            return password
        
        result = list(password)
        i = 0
        while i < len(result) - max_consecutive:
            # Check for consecutive identical characters
            if all(result[i] == result[i + j] for j in range(max_consecutive + 1)):
                # Replace the extra character
                available_chars = [c for c in self.character_sets['lowercase'] + 
                                 self.character_sets['uppercase'] + 
                                 self.character_sets['digits'] 
                                 if c != result[i]]
                if available_chars:
                    result[i + max_consecutive] = secrets.choice(available_chars)
            i += 1
        
        return ''.join(result)
    
    def _ensure_min_char_types(self, password: str, min_types: Dict[str, int]) -> str:
        """Ensure password meets minimum character type requirements"""
        result = list(password)
        
        for char_type, min_count in min_types.items():
            if char_type in self.character_sets:
                current_count = sum(1 for c in result if c in self.character_sets[char_type])
                
                if current_count < min_count:
                    # Replace random characters to meet requirement
                    needed = min_count - current_count
                    char_set = self.character_sets[char_type]
                    
                    for _ in range(needed):
                        if result:  # Make sure we have characters to replace
                            replace_index = secrets.randbelow(len(result))
                            result[replace_index] = secrets.choice(char_set)
        
        return ''.join(result)
    
    def _avoid_weak_patterns(self, password: str) -> str:
        """Check and modify password to avoid weak patterns"""
        password_lower = password.lower()
        
        for pattern in self.weak_patterns:
            if pattern in password_lower:
                # Replace part of the pattern with random characters
                start_idx = password_lower.find(pattern)
                end_idx = start_idx + len(pattern)
                
                # Replace middle characters of the pattern
                replacement_chars = []
                for i in range(start_idx, end_idx):
                    if i < len(password):
                        replacement_chars.append(secrets.choice(
                            self.character_sets['lowercase'] + 
                            self.character_sets['digits']
                        ))
                
                password = password[:start_idx] + ''.join(replacement_chars) + password[end_idx:]
                break
        
        return password
    
    def _evaluate_password_quality(self, password: str, custom_rules: Dict = None) -> float:
        """Evaluate password quality with comprehensive scoring"""
        if not password:
            return 0.0
        
        score = 0.0
        
        # Basic strength analysis
        strength = validate_password_strength(password)
        score += strength['score'] * 0.6  # 60% weight for basic strength
        
        # Entropy analysis
        entropy_data = crypto_manager.calculate_entropy(password)
        if entropy_data['entropy'] > 50:
            score += 20
        elif entropy_data['entropy'] > 30:
            score += 10
        
        # Pattern analysis
        if not any(pattern in password.lower() for pattern in self.weak_patterns):
            score += 10
        
        # Character distribution analysis
        char_types_present = sum([
            any(c.islower() for c in password),
            any(c.isupper() for c in password),
            any(c.isdigit() for c in password),
            any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        ])
        score += char_types_present * 2.5
        
        return min(score, 100.0)  # Cap at 100
    
    def _generate_password_metadata(self, password: str, complexity: Dict, char_pool: Dict) -> Dict[str, any]:
        """Generate comprehensive metadata for the password"""
        strength_analysis = validate_password_strength(password)
        entropy_data = crypto_manager.calculate_entropy(password)
        
        # Character analysis
        char_analysis = {
            'has_lowercase': any(c.islower() for c in password),
            'has_uppercase': any(c.isupper() for c in password),
            'has_digits': any(c.isdigit() for c in password),
            'has_special': any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password),
            'lowercase_count': sum(1 for c in password if c.islower()),
            'uppercase_count': sum(1 for c in password if c.isupper()),
            'digit_count': sum(1 for c in password if c.isdigit()),
            'special_count': sum(1 for c in password if c in "!@#$%^&*()_+-=[]{}|;:,.<>?"),
            'unique_chars': len(set(password))
        }
        
        return {
            'strength_analysis': strength_analysis,
            'entropy_data': entropy_data,
            'character_analysis': char_analysis,
            'generation_info': {
                'char_pool_size': char_pool['pool_size'],
                'used_sets': char_pool['used_sets'],
                'complexity_requested': complexity,
                'excluded_ambiguous': char_pool.get('excluded_ambiguous', False),
                'excluded_similar': char_pool.get('excluded_similar', False)
            },
            'security_metrics': {
                'randomness_source': 'secrets.SystemRandom',
                'generation_algorithm': 'constraint_based_shuffle',
                'quality_score': self._evaluate_password_quality(password)
            }
        }
    
    def _update_generation_stats(self, metadata: Dict):
        """Update internal generation statistics"""
        self.generation_stats['total_generated'] += 1
        self.generation_stats['last_generation'] = datetime.now().isoformat()
        
        # Update average strength
        current_strength = metadata['strength_analysis']['score']
        total = self.generation_stats['total_generated']
        prev_avg = self.generation_stats['average_strength']
        
        self.generation_stats['average_strength'] = (
            (prev_avg * (total - 1) + current_strength) / total
        )
    
    # ==================== BATCH GENERATION ====================
    
    def generate_multiple_passwords(self, count: int, **kwargs) -> List[Dict[str, any]]:
        """Generate multiple passwords with the same parameters"""
        if count <= 0 or count > 100:  # Reasonable limit
            return []
        
        passwords = []
        for i in range(count):
            result = self.generate_password(**kwargs)
            if result['success']:
                passwords.append(result)
        
        return passwords
    
    # ==================== PRESET CONFIGURATIONS ====================
    
    def get_preset_configs(self) -> Dict[str, Dict]:
        """Get predefined password generation presets"""
        return {
            'basic': {
                'length': 8,
                'complexity': {'lowercase': True, 'uppercase': True, 'digits': True, 'special': False},
                'description': 'Basic password for low-security applications'
            },
            'standard': {
                'length': 12,
                'complexity': {'lowercase': True, 'uppercase': True, 'digits': True, 'special': True},
                'description': 'Standard password for most applications'
            },
            'high_security': {
                'length': 16,
                'complexity': {'lowercase': True, 'uppercase': True, 'digits': True, 'special': True},
                'exclude_ambiguous': True,
                'custom_rules': {'avoid_common_patterns': True, 'no_consecutive_identical': True},
                'description': 'High-security password for sensitive applications'
            },
            'maximum_security': {
                'length': 24,
                'complexity': {'lowercase': True, 'uppercase': True, 'digits': True, 'special': True},
                'exclude_ambiguous': True,
                'exclude_similar': True,
                'custom_rules': {
                    'avoid_common_patterns': True,
                    'no_consecutive_identical': True,
                    'min_char_types': {'lowercase': 2, 'uppercase': 2, 'digits': 2, 'special': 2}
                },
                'description': 'Maximum security password for critical systems'
            },
            'pin_code': {
                'length': 6,
                'complexity': {'lowercase': False, 'uppercase': False, 'digits': True, 'special': False},
                'description': 'Numeric PIN code'
            }
        }
    
    def generate_from_preset(self, preset_name: str, **override_params) -> Dict[str, any]:
        """Generate password using a preset configuration with optional overrides"""
        presets = self.get_preset_configs()
        
        if preset_name not in presets:
            return {
                'success': False,
                'error': f'Unknown preset: {preset_name}. Available: {list(presets.keys())}',
                'password': None
            }
        
        # Get preset config and apply overrides
        config = presets[preset_name].copy()
        config.pop('description', None)  # Remove description from generation params
        config.update(override_params)
        
        return self.generate_password(**config)
    
    # ==================== STATISTICS ====================
    
    def get_generation_statistics(self) -> Dict[str, any]:
        """Get password generation statistics"""
        return self.generation_stats.copy()
