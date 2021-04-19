import { useState } from "react";
import { useHistory } from "react-router-dom";
import { CopyToClipboard } from 'react-copy-to-clipboard';
import { AiOutlineCopy } from 'react-icons/ai'
import CreateProcessCalc from "./Attachments/KnowledgeBaseFiles/Exploits/Shellcode Exploits/Calc.exe/CreateProcessCalc.json"
import CreateProcessCalcHalt from "./Attachments/KnowledgeBaseFiles/Exploits/Shellcode Exploits/Calc.exe/CreateProcessCalcHalt.json"
import { CreateProcessCalcDisas, CreateProcessCalcDisasHalt, CreateProcessNotepadDisas, CreateProcessNotepadDisasHalt, SwapMouseButtonOnDisas, SwapMouseButtonOffDisas } from './text-file-reader';
import { SwapMouseButtonOffDisasNSE, SwapMouseButtonOnDisasNSE, SwapMouseButtonOffDisasHalt, SwapMouseButtonOnDisasHalt, MsgBoxADisas, MsgBoxANPDisas} from './text-file-reader';
import { MsgBoxANSEDisas, MsgBoxANP_NSEDisas, MsgBoxAHaltDisas, MsgBoxANP_HaltDisas , WinExecCalcDisas, WinExecCalcHaltDisas, WinExecNotepadDisas, WinExecNotepadHaltDisas} from './text-file-reader';
import CreateProcessNotePad from "./Attachments/KnowledgeBaseFiles/Exploits/Shellcode Exploits/Notepad.exe/CreateProcessNotePad.json"
import CreateProcessNotePadHalt from "./Attachments/KnowledgeBaseFiles/Exploits/Shellcode Exploits/Notepad.exe/CreateProcessNotePadHalt.json"
import SwapMouseButtonOn from "./Attachments/KnowledgeBaseFiles/Exploits/Shellcode Exploits/SwapMouseButton/SwapMouseButtonOn.json"
import SwapMouseButtonOnSafeExit from "./Attachments/KnowledgeBaseFiles/Exploits/Shellcode Exploits/SwapMouseButton/SwapMouseButtonOnSafeExit.json"
import SwapMouseButtonOnHaltExit from "./Attachments/KnowledgeBaseFiles/Exploits/Shellcode Exploits/SwapMouseButton/SwapMouseButtonOnHaltExit.json"
import SwapMouseButtonOff from "./Attachments/KnowledgeBaseFiles/Exploits/Shellcode Exploits/SwapMouseButton/SwapMouseButtonOff.json"
import SwapMouseButtonOffSafeExit from "./Attachments/KnowledgeBaseFiles/Exploits/Shellcode Exploits/SwapMouseButton/SwapMouseButtonOffSafeExit.json"
import SwapMouseButtonOffHaltExit from "./Attachments/KnowledgeBaseFiles/Exploits/Shellcode Exploits/SwapMouseButton/SwapMouseButtonOffHaltExit.json"
import MsgBoxA from "./Attachments/KnowledgeBaseFiles/Exploits/Shellcode Exploits/MessageBoxA/MsgBoxA.json"
import MsgBoxANP from "./Attachments/KnowledgeBaseFiles/Exploits/Shellcode Exploits/MessageBoxA/MsgBoxANP.json"
import MsgBoxAHalt from "./Attachments/KnowledgeBaseFiles/Exploits/Shellcode Exploits/MessageBoxA/MsgBoxAHalt.json"
import MsgBoxANP_Halt from "./Attachments/KnowledgeBaseFiles/Exploits/Shellcode Exploits/MessageBoxA/MsgBoxANP_Halt.json"
import MsgBoxANSE from "./Attachments/KnowledgeBaseFiles/Exploits/Shellcode Exploits/MessageBoxA/MsgBoxANSE.json"
import MsgBoxANP_NSE from "./Attachments/KnowledgeBaseFiles/Exploits/Shellcode Exploits/MessageBoxA/MsgBoxANP_NSE.json"

const ShellcodeGenerator = () => {

  const [StandardDLL, setStandardDLL] = useState("");
  const [DLLFunction, setDLLFunction] = useState("");
  const [FunctionArgument, setFunctionArgument] = useState("");
  const [Exit, setExit] = useState("");
  const [ShellcodeGenerated, setShellcodeGenerated] = useState("");
  const [DisassemblyGenerated, setDisassemblyGenerated] = useState("");

  /** Function that will set different values to state variable 
 * based on which dropdown is selected 
 */
  const changeSelectOptionHandler = (event) => {
    setStandardDLL(event.target.value);
  };
  const changeSelect2OptionHandler = (event) => {
    setDLLFunction(event.target.value);
  };
  const changeSelect3OptionHandler = (event) => {
    setFunctionArgument(event.target.value);
  };
  const changeSelect4OptionHandler = (event) => {
    setExit(event.target.value);
  };

  /** Different arrays for different dropdowns */
  const Kernel32Functions = ["--Select--", "CreateProcessA()", "WinExec()"];
  const User32Functions = ["--Select--", "SwapMouseButton()", "MessageBoxA()"];
  const CmdArguements = ["--Select--", "Calc.exe", "Notepad.exe"];
  const ExitMethods = ["--Select--", "None", "Safe Exit", "Halt"];
  const ExitMethodsR = ["--Select--", "None", "Halt"];
  const SwapMouseButtonStates = ["--Select--", "True", "False"];
  const MessageBoxAArguements = ["--Select--", "With Arguments", "Without Arguments"];
  const EmptySelect = ["--Select--"];

  /** Type variable to store different array for different dropdown */
  let DropDown2 = null;
  let DropDown3 = null;
  let DropDown4 = null;

  /** This will be used to create set of options that user will see */
  let options2 = null;
  let options3 = null;
  let options4 = null;

  /** Setting Type variable according to dropdown */
  if (StandardDLL === "Kernel32.dll") {
    DropDown2 = Kernel32Functions;
    DropDown3 = CmdArguements;
    DropDown4 = ExitMethodsR;
  }
  if (StandardDLL === "User32.dll") {
    DropDown2 = User32Functions;
    DropDown3 = EmptySelect;
    DropDown4 = ExitMethods;
    if (DLLFunction === "SwapMouseButton()") {
      DropDown3 = SwapMouseButtonStates;
    }
    if (DLLFunction === "MessageBoxA()") {
      DropDown3 = MessageBoxAArguements;
    }
  }

  /** If "DropDown" is null or undefined then options will be null, 
   * otherwise it will create a options iterable based on our array 
   */
  if (DropDown2) {
    options2 = DropDown2.map((el) => <option key={el}>{el}</option>);
  }
  if (DropDown3) {
    options3 = DropDown3.map((el) => <option key={el}>{el}</option>);
  }
  if (DropDown4) {
    options4 = DropDown4.map((el) => <option key={el}>{el}</option>);
  }

  const handleSubmit = (e) => {
    e.preventDefault();
    if (DLLFunction === "CreateProcessA()") {
      if (FunctionArgument === "Calc.exe") {
        if (Exit === "None") {
          setShellcodeGenerated(CreateProcessCalc);
          setDisassemblyGenerated(CreateProcessCalcDisas);
        } else if (Exit === "Halt") {
          setShellcodeGenerated(CreateProcessCalcHalt);
          setDisassemblyGenerated(CreateProcessCalcDisasHalt);
        }
      } else if (FunctionArgument === "Notepad.exe") {
        if (Exit === "None") {
          setShellcodeGenerated(CreateProcessNotePad);
          setDisassemblyGenerated(CreateProcessNotepadDisas);
        } else if (Exit === "Halt") {
          setShellcodeGenerated(CreateProcessNotePadHalt);
          setDisassemblyGenerated(CreateProcessNotepadDisasHalt);
        }
      }
    } else if (DLLFunction === "SwapMouseButton()") {
      if (FunctionArgument === "True") {
        if (Exit === "None") {
          setShellcodeGenerated(SwapMouseButtonOn);
          setDisassemblyGenerated(SwapMouseButtonOnDisasNSE);
        } else if (Exit === "Halt") {
          setShellcodeGenerated(SwapMouseButtonOnHaltExit);
          setDisassemblyGenerated(SwapMouseButtonOnDisasHalt);
        } else if (Exit === "Safe Exit") {
          setShellcodeGenerated(SwapMouseButtonOnSafeExit);
          setDisassemblyGenerated(SwapMouseButtonOnDisas);
        }
      } else if (FunctionArgument === "False") {
        if (Exit === "None") {
          setShellcodeGenerated(SwapMouseButtonOff);
          setDisassemblyGenerated(SwapMouseButtonOffDisasNSE);
        } else if (Exit === "Halt") {
          setShellcodeGenerated(SwapMouseButtonOffHaltExit);
          setDisassemblyGenerated(SwapMouseButtonOffDisasHalt);
        } else if (Exit === "Safe Exit") {
          setShellcodeGenerated(SwapMouseButtonOffSafeExit);
          setDisassemblyGenerated(SwapMouseButtonOffDisas);
        }
      }
    } else if (DLLFunction === "MessageBoxA()") {
      if (FunctionArgument === "With Arguments") {
        if (Exit === "None") {
          setShellcodeGenerated(MsgBoxANSE);
          setDisassemblyGenerated(MsgBoxANSEDisas);
        } else if (Exit === "Halt") {
          setShellcodeGenerated(MsgBoxAHalt);
          setDisassemblyGenerated(MsgBoxAHaltDisas);
        } else if (Exit === "Safe Exit") {
          setShellcodeGenerated(MsgBoxA);
          setDisassemblyGenerated(MsgBoxADisas);
        }
      } else if (FunctionArgument === "Without Arguments") {
        if (Exit === "None") {
          setShellcodeGenerated(MsgBoxANP_NSE);
          setDisassemblyGenerated(MsgBoxANP_NSEDisas);
        } else if (Exit === "Halt") {
          setShellcodeGenerated(MsgBoxANP_Halt);
          setDisassemblyGenerated(MsgBoxANP_HaltDisas);
        } else if (Exit === "Safe Exit") {
          setShellcodeGenerated(MsgBoxANP);
          setDisassemblyGenerated(MsgBoxANPDisas);
        }
      }
    } else if (DLLFunction === "WinExec()") {
      if (FunctionArgument === "Calc.exe") {
        if (Exit === "None") {
          setShellcodeGenerated(CreateProcessCalc);
          setDisassemblyGenerated(WinExecCalcDisas);
        } else if (Exit === "Halt") {
          setShellcodeGenerated(CreateProcessCalcHalt);
          setDisassemblyGenerated(WinExecCalcHaltDisas);
        }
      } else if (FunctionArgument === "Notepad.exe") {
        if (Exit === "None") {
          setShellcodeGenerated(CreateProcessNotePad);
          setDisassemblyGenerated(WinExecNotepadDisas);
        } else if (Exit === "Halt") {
          setShellcodeGenerated(CreateProcessNotePadHalt);
          setDisassemblyGenerated(WinExecNotepadHaltDisas);
        }
      }
    }
  }
  /* -------------------------------------------------------------------------------------- */

  return (
    <div className="shellcodegenerator">
      <br />
      <h6><b style={{ color: "#242582" }}>Shellcode Generator</b></h6>
      <br />
      <form onSubmit={handleSubmit}>
        <div className="sidebyside">
          <div className="above">
            <label>Standard DLL:</label>
            <select onChange={changeSelectOptionHandler}>
              <option>--Select--</option>
              <option>User32.dll</option>
              <option>Kernel32.dll</option>
            </select>
          </div>
          <div className="above">
            <label>DLL Functions:</label>
            <select onChange={changeSelect2OptionHandler}>
              {
                /** This is where we have used our options variable */
                options2
              }
            </select>
          </div>
          <div className="above">
            <label>Function Arguements:</label>
            <select onChange={changeSelect3OptionHandler}>
              {
                /** This is where we have used our options variable */
                options3
              }
            </select>
          </div>
          <div className="above">
            <label>Exit Method:</label>
            <select onChange={changeSelect4OptionHandler}>
              {
                /** This is where we have used our options variable */
                options4
              }
            </select>
          </div>
          <br />
        </div>
        <button className="genbtn">Generate</button>
      </form>
      <br />
      <h3> Shellcode :         <CopyToClipboard text={ShellcodeGenerated}>
          <button className="cpybtn"><AiOutlineCopy /></button>
        </CopyToClipboard></h3>
      <div className="generated">
        <p><br />{ShellcodeGenerated}</p>
        <br />
      </div>
      <br />
      <h3> Disassembly : </h3>
      <div className="disasgenerated">
        <p><br />{DisassemblyGenerated}</p>
      </div>
      <br />
    </div>
  );
}

export default ShellcodeGenerator;