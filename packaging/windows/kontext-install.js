// Deferred custom actions of the Kontext MSI (Package.wxs). Windows Installer
// runs them as LocalSystem, in its own 64-bit script host: no process is
// started and no value passes through a command line. Each reads its input
// from CustomActionData, which Package.wxs sets in an immediate action and
// keeps out of the installer log. Each returns 1 on success and 3 on failure.
//
// JScript 5 (ES3): no JSON, no String.prototype.trim, no Array.prototype.indexOf.

var SUCCESS = 1;
var FAILURE = 3;

var CONFIG_FILE = "managed.json";
// Left beside managed.json while the install can still roll back: the file it
// replaced, or an empty marker saying there was none.
var BACKUP = ".msi-backup";
var CREATED = ".msi-created";

// The install token: a REG_SZ under the machine policy key, in the 64-bit view.
// Only administrators and SYSTEM can write there and users can read; the
// installer leaves the key's access list as Windows sets it. An MDM can set the
// same value through an ADMX policy. The rollback copies use the suffixes above.
var TOKEN_KEY = "SOFTWARE\\Policies\\Kontext";
var TOKEN_VALUE = "InstallToken";

var TASK_FOLDER = "Kontext";
var TASK_NAME = "Kontext Daemon";
var TASK_PLACEHOLDER = "@KONTEXTW_EXE@";
var TASK_CREATE_OR_UPDATE = 6;
var TASK_LOGON_GROUP = 4;

// WriteConfig writes managed.json when CLOUD_URL is set, as a new file that
// inherits the folder's access list, and the token value when INSTALL_TOKEN is
// set. CustomActionData: folder|CLOUD_URL|MODE|INSTALL_TOKEN.
function WriteConfig() {
    return run("write the configuration", function () {
        var f = fields(4), dir = folder(f[0]), url = f[1], mode = f[2], token = f[3];
        if (url !== "") {
            if (!/^https:\/\/[\x21-\x7e]+$/.test(url) || /["\\|]/.test(url)) {
                throw new Error("CLOUD_URL must be an https URL of printable ASCII characters");
            }
            if (mode !== "observe" && mode !== "enforce") {
                throw new Error("MODE must be observe or enforce");
            }
        }
        if (token !== "" && !/^[\x21-\x7e]+$/.test(token)) {
            throw new Error("INSTALL_TOKEN must be printable ASCII characters without spaces");
        }
        if (url !== "") {
            replaceFile(new ActiveXObject("Scripting.FileSystemObject"), dir + CONFIG_FILE, configJSON(url, mode));
        }
        if (token !== "") {
            replaceToken(new Registry(), token);
        }
    });
}

// RollbackConfig puts back what WriteConfig replaced. CustomActionData: folder.
function RollbackConfig() {
    return run("roll back the configuration", function () {
        var fso = new ActiveXObject("Scripting.FileSystemObject");
        var path = folder(fields(1)[0]) + CONFIG_FILE;
        if (fso.FileExists(path + BACKUP)) {
            removeFile(fso, path);
            fso.MoveFile(path + BACKUP, path);
            log("restored " + path);
        } else if (fso.FileExists(path + CREATED)) {
            removeFile(fso, path);
            log("removed " + path);
        }
        removeFile(fso, path + CREATED);

        var reg = new Registry();
        var old = reg.get(TOKEN_KEY, TOKEN_VALUE + BACKUP);
        if (old !== null) {
            reg.set(TOKEN_KEY, TOKEN_VALUE, old);
            log("restored the install token");
        } else if (reg.get(TOKEN_KEY, TOKEN_VALUE + CREATED) !== null) {
            reg.remove(TOKEN_KEY, TOKEN_VALUE);
            log("removed the install token");
        }
        dropTokenCopies(reg);
    });
}

// CommitConfig drops the rollback copies once the install has succeeded.
// CustomActionData: folder.
function CommitConfig() {
    return run("finish the configuration", function () {
        var fso = new ActiveXObject("Scripting.FileSystemObject");
        var path = folder(fields(1)[0]) + CONFIG_FILE;
        removeFile(fso, path + BACKUP);
        removeFile(fso, path + CREATED);
        dropTokenCopies(new Registry());
    });
}

// RemoveConfig deletes managed.json and the token value on uninstall, and the
// token key if nothing else is left in it. CustomActionData: folder.
function RemoveConfig() {
    return run("remove the configuration", function () {
        var fso = new ActiveXObject("Scripting.FileSystemObject");
        var path = folder(fields(1)[0]) + CONFIG_FILE;
        removeFile(fso, path);
        removeFile(fso, path + BACKUP);
        removeFile(fso, path + CREATED);
        var reg = new Registry();
        reg.remove(TOKEN_KEY, TOKEN_VALUE);
        dropTokenCopies(reg);
        if (reg.removeKeyIfEmpty(TOKEN_KEY)) {
            log("removed HKLM\\" + TOKEN_KEY);
        }
    });
}

// replaceToken writes the token value and keeps what it replaced for
// RollbackConfig.
function replaceToken(reg, token) {
    dropTokenCopies(reg);
    var old = reg.get(TOKEN_KEY, TOKEN_VALUE);
    if (old !== null) {
        reg.set(TOKEN_KEY, TOKEN_VALUE + BACKUP, old);
    } else {
        reg.set(TOKEN_KEY, TOKEN_VALUE + CREATED, "");
    }
    reg.set(TOKEN_KEY, TOKEN_VALUE, token);
    log("wrote HKLM\\" + TOKEN_KEY + "\\" + TOKEN_VALUE);
}

function dropTokenCopies(reg) {
    reg.remove(TOKEN_KEY, TOKEN_VALUE + BACKUP);
    reg.remove(TOKEN_KEY, TOKEN_VALUE + CREATED);
}

// Registry reads and writes string values with WScript.Shell and lists a key
// with Installer.RegistryValue. The custom actions run in a 64-bit script host,
// so both see the 64-bit view.
var REG_ROOT = "HKLM";
var REG_ROOT_ID = 2; // msiRegistryRootLocalMachine

function Registry() {
    this.shell = new ActiveXObject("WScript.Shell");
    this.installer = Session.Installer;
}

Registry.prototype.path = function (key, name) {
    return REG_ROOT + "\\" + key + "\\" + name;
};

// get returns the value, or null if the key or value is missing.
Registry.prototype.get = function (key, name) {
    try {
        return String(this.shell.RegRead(this.path(key, name)));
    } catch (e) {
        return null;
    }
};

// set creates the key if needed and writes a REG_SZ.
Registry.prototype.set = function (key, name, value) {
    this.shell.RegWrite(this.path(key, name), value, "REG_SZ");
};

// remove deletes a value; a missing key or value is not an error.
Registry.prototype.remove = function (key, name) {
    if (this.get(key, name) !== null) {
        this.shell.RegDelete(this.path(key, name));
    }
};

// removeKeyIfEmpty deletes key when it holds no named values and no subkeys,
// and reports whether it did. RegistryValue counts values from 1 and subkeys
// from -1.
Registry.prototype.removeKeyIfEmpty = function (key) {
    if (!this.installer.RegistryValue(REG_ROOT_ID, key)) {
        return false;
    }
    if (present(this.installer.RegistryValue(REG_ROOT_ID, key, 1)) || present(this.installer.RegistryValue(REG_ROOT_ID, key, -1))) {
        return false;
    }
    this.shell.RegDelete(REG_ROOT + "\\" + key + "\\");
    return true;
};

function present(name) {
    return typeof name !== "undefined" && name !== null && String(name) !== "";
}

// RegisterTask registers the logon task from the shipped task XML, with the
// installed kontextw.exe filled in. CustomActionData: task XML|kontextw.exe.
function RegisterTask() {
    return run("register the logon task", function () {
        var f = fields(2);
        var service = taskService();
        var definition = service.NewTask(0);
        definition.XmlText = taskXML(f[0], f[1]);
        // The XML names the group by SID; Task Scheduler reads it back as this
        // system's name for it, which is what registration takes.
        var group = definition.Principal.GroupId;
        var none; // VT_EMPTY: a group needs no password.
        taskFolder(service, true).RegisterTaskDefinition(TASK_NAME, definition, TASK_CREATE_OR_UPDATE, group, none, TASK_LOGON_GROUP);
        log("registered \\" + TASK_FOLDER + "\\" + TASK_NAME);
    });
}

// UnregisterTask stops the daemons the task started and deletes the task, and
// its folder if nothing else is in it. A missing task is not an error.
function UnregisterTask() {
    return run("remove the logon task", function () {
        var service = taskService();
        var tasks = taskFolder(service, false);
        if (tasks === null) {
            return;
        }
        var task = null;
        try {
            task = tasks.GetTask(TASK_NAME);
        } catch (e) {
            return;
        }
        try {
            task.Stop(0);
        } catch (e) {
            log("could not stop the running daemons: " + describe(e));
        }
        tasks.DeleteTask(TASK_NAME, 0);
        log("removed \\" + TASK_FOLDER + "\\" + TASK_NAME);
        try {
            service.GetFolder("\\").DeleteFolder(TASK_FOLDER, 0);
        } catch (e) {
            // Not empty: someone else's task is in it.
        }
    });
}

function taskXML(templatePath, exe) {
    var fso = new ActiveXObject("Scripting.FileSystemObject");
    var stream = fso.OpenTextFile(templatePath, 1, false, 0);
    var xml = stream.ReadAll();
    stream.Close();
    var parts = xml.split(TASK_PLACEHOLDER);
    if (parts.length !== 2) {
        throw new Error(templatePath + " must name " + TASK_PLACEHOLDER + " exactly once");
    }
    return parts.join(xmlEscape(exe));
}

function taskService() {
    var service = new ActiveXObject("Schedule.Service");
    service.Connect();
    return service;
}

function taskFolder(service, create) {
    try {
        return service.GetFolder("\\" + TASK_FOLDER);
    } catch (e) {
        if (!create) {
            return null;
        }
        return service.GetFolder("\\").CreateFolder(TASK_FOLDER);
    }
}

// replaceFile writes text to path as a new file, so its owner is the installer
// and its access list the folder's, whoever owned a file there before. What it
// replaces is kept for RollbackConfig.
function replaceFile(fso, path, text) {
    removeFile(fso, path + BACKUP);
    removeFile(fso, path + CREATED);
    if (fso.FileExists(path)) {
        fso.MoveFile(path, path + BACKUP);
    } else {
        fso.CreateTextFile(path + CREATED, true, false).Close();
    }
    var stream = fso.CreateTextFile(path, true, false);
    stream.Write(text);
    stream.Close();
    log("wrote " + path);
}

function removeFile(fso, path) {
    if (fso.FileExists(path)) {
        fso.DeleteFile(path, true);
    }
}

// configJSON is the format internal/managedconfig reads. The token is the
// InstallToken value under the policy key.
function configJSON(url, mode) {
    return "{\n" +
        "  \"version\": \"managed-install-v1\",\n" +
        "  \"cloud_url\": \"" + jsonEscape(url) + "\",\n" +
        "  \"mode\": \"" + jsonEscape(mode) + "\",\n" +
        "  \"agent\": \"claude\",\n" +
        "  \"credentials\": {\n" +
        "    \"install_token_ref\": \"registry:" + TOKEN_VALUE + "\"\n" +
        "  }\n" +
        "}\n";
}

function jsonEscape(s) {
    return s.replace(/\\/g, "\\\\").replace(/"/g, "\\\"");
}

function xmlEscape(s) {
    return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;").replace(/'/g, "&apos;");
}

function folder(path) {
    if (path === "") {
        throw new Error("no folder given");
    }
    return path.charAt(path.length - 1) === "\\" ? path : path + "\\";
}

// fields splits CustomActionData into count fields on "|". The last field
// takes the rest, so it may contain "|".
function fields(count) {
    var data = String(Session.Property("CustomActionData"));
    var out = [];
    for (var i = 1; i < count; i++) {
        var at = data.indexOf("|");
        if (at < 0) {
            throw new Error("CustomActionData has " + i + " fields, want " + count);
        }
        out.push(data.substring(0, at));
        data = data.substring(at + 1);
    }
    out.push(data);
    return out;
}

// run calls body and turns an exception into a logged failure. Messages name
// paths and properties, never a property's value.
function run(what, body) {
    try {
        body();
        return SUCCESS;
    } catch (e) {
        log("could not " + what + ": " + describe(e));
        return FAILURE;
    }
}

function describe(e) {
    var text = e.message || e.description || String(e);
    if (typeof e.number === "number" && e.number !== 0) {
        text += " (0x" + (e.number >>> 0).toString(16) + ")";
    }
    return text;
}

function log(text) {
    try {
        var record = Session.Installer.CreateRecord(1);
        record.StringData(0) = "Kontext: [1]";
        record.StringData(1) = text;
        Session.Message(0x04000000, record); // INSTALLMESSAGE_INFO
    } catch (e) {
        // Logging must not fail the action.
    }
}
