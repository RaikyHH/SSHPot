"""
Dynamic Values Handler for SSHPot Honeypot

This module processes dynamic values in command outputs, allowing for:
- Random values within ranges
- Incrementing/decrementing counters
- Time-based values (uptime, timestamps)
- Session-specific persistent values

Defensive Security Tool - Does NOT execute actual commands
"""

import re
import time
import random
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import json


@dataclass
class DynamicValueState:
    """Tracks state for dynamic values across sessions"""
    # Global state (shared across all sessions)
    global_counters: Dict[str, float] = field(default_factory=dict)
    global_start_time: float = field(default_factory=time.time)

    # Session-specific state
    session_counters: Dict[str, Dict[str, float]] = field(default_factory=dict)
    session_start_times: Dict[str, float] = field(default_factory=dict)


class DynamicValueProcessor:
    """
    Processes dynamic value placeholders in command outputs

    Supported Syntax:

    1. Random Values:
       {{random:min:max}}                    - Random integer between min and max
       {{random:min:max:precision}}          - Random float with precision decimal places
       {{random_choice:option1|option2|...}} - Random choice from options

    2. Incrementing/Decrementing Values:
       {{counter:name:start:increment}}      - Global counter that increments
       {{counter:name:start:increment:max}}  - Counter with wraparound at max
       {{session_counter:name:start:inc}}    - Per-session counter

    3. Time-Based Values:
       {{uptime}}                            - Global uptime (HH:MM:SS format)
       {{uptime_days}}                       - Global uptime in "X days, HH:MM" format
       {{session_uptime}}                    - Per-session uptime
       {{timestamp}}                         - Current Unix timestamp
       {{datetime:format}}                   - Current datetime with custom format

    4. Calculated Values:
       {{calc:expression}}                   - Evaluate expression (safe math only)
       {{percent:value:total}}               - Calculate percentage

    5. Conditional Values:
       {{if:condition:true_val:false_val}}   - Conditional output

    Examples:
    - "load average: {{random:0.00:0.05:2}}, {{random:0.01:0.10:2}}, {{random:0.05:0.20:2}}"
    - "up {{uptime_days}}, 1 user"
    - "CPU: {{random:0:100}}%"
    - "PID {{counter:pid:1000:1:65535}}"
    """

    def __init__(self, state: Optional[DynamicValueState] = None):
        """
        Initialize the dynamic value processor

        Args:
            state: Optional state object for persistent values
        """
        self.state = state or DynamicValueState()
        # Pattern matches {{...}} - non-greedy to handle multiple placeholders
        # For nested placeholders, we process multiple passes (innermost first)
        self.pattern = re.compile(r'\{\{([^{}]+)\}\}')

    def process(self, text: str, session_id: Optional[str] = None) -> str:
        """
        Process all dynamic value placeholders in text
        Supports nested placeholders by processing multiple passes

        Args:
            text: Text containing dynamic value placeholders
            session_id: Optional session ID for session-specific values

        Returns:
            Text with all placeholders replaced by actual values
        """
        if session_id and session_id not in self.state.session_start_times:
            self.state.session_start_times[session_id] = time.time()
            self.state.session_counters[session_id] = {}

        def replace_placeholder(match):
            placeholder = match.group(1)
            try:
                return self._evaluate_placeholder(placeholder, session_id)
            except Exception as e:
                # Return placeholder unchanged if evaluation fails
                return f"{{{{{placeholder}}}}}"

        MAX_PASSES = 5
        MAX_TEXT_LENGTH = 1024 * 100
        start_length = len(text)

        for pass_num in range(MAX_PASSES):
            if len(text) > MAX_TEXT_LENGTH:
                print(f"[DynamicValues] Text expansion limit exceeded ({len(text)} bytes)")
                return text[:MAX_TEXT_LENGTH] + "...[truncated]"

            if len(text) > start_length * 10:
                print(f"[DynamicValues] Expansion ratio limit exceeded")
                break

            new_text = self.pattern.sub(replace_placeholder, text)
            if new_text == text:
                break
            text = new_text

        return text

    def _evaluate_placeholder(self, placeholder: str, session_id: Optional[str]) -> str:
        """
        Evaluate a single dynamic value placeholder

        Args:
            placeholder: The placeholder content (without {{ }})
            session_id: Optional session ID

        Returns:
            String representation of the evaluated value
        """
        parts = placeholder.split(':')
        value_type = parts[0]

        if value_type == 'random':
            return self._random_value(parts[1:])

        elif value_type == 'random_choice':
            return self._random_choice(parts[1:])

        elif value_type == 'counter':
            return self._global_counter(parts[1:])

        elif value_type == 'session_counter':
            return self._session_counter(parts[1:], session_id)

        elif value_type == 'uptime':
            return self._global_uptime()

        elif value_type == 'uptime_days':
            return self._global_uptime_days()

        elif value_type == 'session_uptime':
            return self._session_uptime(session_id)

        elif value_type == 'timestamp':
            return str(int(time.time()))

        elif value_type == 'datetime':
            return self._datetime_format(parts[1:])

        elif value_type == 'calc':
            return self._calculate(parts[1:])

        elif value_type == 'percent':
            return self._percentage(parts[1:])

        elif value_type == 'if':
            return self._conditional(parts[1:])

        else:
            raise ValueError(f"Unknown placeholder type: {value_type}")

    def _random_value(self, args: list) -> str:
        """
        Generate random value

        Args:
            args: [min, max] or [min, max, precision]

        Returns:
            Random value as string
        """
        if len(args) < 2:
            raise ValueError("random requires at least min and max")

        min_val = float(args[0])
        max_val = float(args[1])
        precision = int(args[2]) if len(args) > 2 else 0

        if precision == 0:
            return str(random.randint(int(min_val), int(max_val)))
        else:
            value = random.uniform(min_val, max_val)
            return f"{value:.{precision}f}"

    def _random_choice(self, args: list) -> str:
        """
        Random choice from options

        Args:
            args: [options_string] where options are separated by |

        Returns:
            Randomly chosen option
        """
        if not args:
            raise ValueError("random_choice requires options")

        options = args[0].split('|')
        return random.choice(options)

    def _global_counter(self, args: list) -> str:
        """
        Global counter that persists across sessions

        Args:
            args: [name, start, increment] or [name, start, increment, max]

        Returns:
            Current counter value as string
        """
        if len(args) < 3:
            raise ValueError("counter requires name, start, and increment")

        name = args[0]
        start = float(args[1])
        increment = float(args[2])
        max_val = float(args[3]) if len(args) > 3 else None

        if name not in self.state.global_counters:
            self.state.global_counters[name] = start

        current = self.state.global_counters[name]
        self.state.global_counters[name] += increment

        # Wraparound if max specified
        if max_val and self.state.global_counters[name] > max_val:
            self.state.global_counters[name] = start

        # Return as int if no decimal part
        if current == int(current):
            return str(int(current))
        return str(current)

    def _session_counter(self, args: list, session_id: Optional[str]) -> str:
        """
        Per-session counter

        Args:
            args: [name, start, increment]
            session_id: Session identifier

        Returns:
            Current counter value as string
        """
        if not session_id:
            return self._global_counter(args)

        if len(args) < 3:
            raise ValueError("session_counter requires name, start, and increment")

        name = args[0]
        start = float(args[1])
        increment = float(args[2])

        if name not in self.state.session_counters[session_id]:
            self.state.session_counters[session_id][name] = start

        current = self.state.session_counters[session_id][name]
        self.state.session_counters[session_id][name] += increment

        if current == int(current):
            return str(int(current))
        return str(current)

    def _global_uptime(self) -> str:
        """
        Get global uptime in HH:MM:SS format

        Returns:
            Uptime string
        """
        elapsed = int(time.time() - self.state.global_start_time)
        hours = elapsed // 3600
        minutes = (elapsed % 3600) // 60
        seconds = elapsed % 60
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    def _global_uptime_days(self) -> str:
        """
        Get global uptime in "X days, HH:MM" format

        Returns:
            Uptime string
        """
        elapsed = int(time.time() - self.state.global_start_time)
        days = elapsed // 86400
        hours = (elapsed % 86400) // 3600
        minutes = (elapsed % 3600) // 60

        if days > 0:
            return f"{days} day{'s' if days != 1 else ''}, {hours:02d}:{minutes:02d}"
        else:
            return f"{hours:02d}:{minutes:02d}"

    def _session_uptime(self, session_id: Optional[str]) -> str:
        """
        Get per-session uptime in HH:MM:SS format

        Args:
            session_id: Session identifier

        Returns:
            Uptime string
        """
        if not session_id or session_id not in self.state.session_start_times:
            return "00:00:00"

        elapsed = int(time.time() - self.state.session_start_times[session_id])
        hours = elapsed // 3600
        minutes = (elapsed % 3600) // 60
        seconds = elapsed % 60
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    def _datetime_format(self, args: list) -> str:
        """
        Format current datetime

        Args:
            args: [format_string] using strftime format

        Returns:
            Formatted datetime string
        """
        fmt = args[0] if args else "%Y-%m-%d %H:%M:%S"
        return datetime.now().strftime(fmt)

    def _calculate(self, args: list) -> str:
        """
        Safely evaluate mathematical expression using AST parsing.

        Args:
            args: [expression] - simple math expression

        Returns:
            Calculated value as string
        """
        import ast
        import operator

        if not args:
            raise ValueError("calc requires expression")

        expression = args[0]

        # Whitelist allowed characters
        allowed_chars = set('0123456789+-*/(). ')
        if not all(c in allowed_chars for c in expression):
            raise ValueError("Invalid characters in expression")

        # Parse to AST
        try:
            tree = ast.parse(expression, mode='eval')
        except SyntaxError:
            raise ValueError("Invalid expression syntax")

        # Define allowed operations
        ops = {
            ast.Add: operator.add,
            ast.Sub: operator.sub,
            ast.Mult: operator.mul,
            ast.Div: operator.truediv,
            ast.Mod: operator.mod,
            ast.Pow: operator.pow,
            ast.USub: operator.neg
        }

        # Recursively evaluate AST nodes
        def eval_node(node):
            if isinstance(node, ast.Constant):  # Python 3.8+
                return node.value
            elif isinstance(node, ast.Num):  # Python 3.7 compatibility
                return node.n
            elif isinstance(node, ast.BinOp):
                left = eval_node(node.left)
                right = eval_node(node.right)

                if isinstance(node.op, ast.Pow):
                    if abs(left) > 1000 or abs(right) > 100:
                        raise ValueError("Exponent too large")

                if type(node.op) not in ops:
                    raise ValueError(f"Forbidden operation: {type(node.op).__name__}")

                return ops[type(node.op)](left, right)

            elif isinstance(node, ast.UnaryOp):
                if type(node.op) not in ops:
                    raise ValueError(f"Forbidden operation: {type(node.op).__name__}")
                operand = eval_node(node.operand)
                return ops[type(node.op)](operand)

            else:
                raise ValueError(f"Forbidden node type: {type(node).__name__}")

        try:
            result = eval_node(tree.body)

            if isinstance(result, (int, float)):
                if abs(result) > 10**15:
                    raise ValueError("Result too large")

            if isinstance(result, float) and result == int(result):
                return str(int(result))
            return str(result)

        except (ZeroDivisionError, OverflowError) as e:
            raise ValueError(f"Calculation error: {e}")

    def _percentage(self, args: list) -> str:
        """
        Calculate percentage

        Args:
            args: [value, total] or [value, total, precision]

        Returns:
            Percentage as string
        """
        if len(args) < 2:
            raise ValueError("percent requires value and total")

        value = float(args[0])
        total = float(args[1])
        precision = int(args[2]) if len(args) > 2 else 0

        if total == 0:
            return "0"

        pct = (value / total) * 100

        if precision == 0:
            return str(int(pct))
        return f"{pct:.{precision}f}"

    def _conditional(self, args: list) -> str:
        """
        Conditional value based on simple condition

        Args:
            args: [condition, true_value, false_value]
                  condition format: "value operator value" (e.g., "5 > 3")

        Returns:
            true_value or false_value based on condition
        """
        if len(args) < 3:
            raise ValueError("if requires condition, true_value, false_value")

        condition = args[0]
        true_val = args[1]
        false_val = args[2]

        # Simple condition evaluation (very basic)
        # Support: ==, !=, <, >, <=, >=
        operators = ['==', '!=', '<=', '>=', '<', '>']

        for op in operators:
            if op in condition:
                left, right = condition.split(op, 1)
                left = left.strip()
                right = right.strip()

                # Try to convert to numbers
                try:
                    left_num = float(left)
                    right_num = float(right)

                    if op == '==':
                        result = left_num == right_num
                    elif op == '!=':
                        result = left_num != right_num
                    elif op == '<':
                        result = left_num < right_num
                    elif op == '>':
                        result = left_num > right_num
                    elif op == '<=':
                        result = left_num <= right_num
                    elif op == '>=':
                        result = left_num >= right_num

                    return true_val if result else false_val
                except ValueError:
                    # String comparison
                    if op == '==':
                        result = left == right
                    elif op == '!=':
                        result = left != right
                    else:
                        return false_val

                    return true_val if result else false_val

        return false_val

    def serialize_state(self) -> str:
        """
        Serialize the state to JSON for persistence

        Returns:
            JSON string of state
        """
        return json.dumps({
            'global_counters': self.state.global_counters,
            'global_start_time': self.state.global_start_time,
            'session_counters': self.state.session_counters,
            'session_start_times': self.state.session_start_times
        })

    @classmethod
    def deserialize_state(cls, json_str: str) -> 'DynamicValueProcessor':
        """
        Deserialize state from JSON

        Args:
            json_str: JSON string of state

        Returns:
            DynamicValueProcessor with restored state
        """
        data = json.loads(json_str)
        state = DynamicValueState(
            global_counters=data['global_counters'],
            global_start_time=data['global_start_time'],
            session_counters=data['session_counters'],
            session_start_times=data['session_start_times']
        )
        return cls(state)
