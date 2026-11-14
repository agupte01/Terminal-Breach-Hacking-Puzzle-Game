/*
 * levels.c — Level definitions for all 45 stages of Terminal Breach.
 *
 * Each init_levelN function initialises one Level struct in the global array,
 * populating its nodes and files using the shorthand macros defined below.
 * All level data is set once at startup and treated as read-only during play.
 * Mutable state (file unlocks, decryption flags, detection) lives in GameState.
 *
 * Cipher values are verified: every encoded string decodes to the expected
 * plaintext using the algorithm in puzzles.c with the stored shift.
 */

#include "levels.h"
#include <string.h>

Level levels[TOTAL_LEVELS];

/* Appends a new node to the level's node array and initialises its fields.
   The node index is determined by the current node_count before the increment. */
static void add_node(Level *l, const char *ip, const char *hostname,
                     const char *desc, Permission min_perm, int is_entry) {
    int i = l->node_count++;
    strncpy(l->nodes[i].ip,          ip,       MAX_NODE_IP   - 1);
    strncpy(l->nodes[i].hostname,    hostname, MAX_NODE_NAME - 1);
    strncpy(l->nodes[i].description, desc,     255);
    l->nodes[i].min_perm    = min_perm;
    l->nodes[i].is_entry    = is_entry;
    l->nodes[i].file_count  = 0;
    l->nodes[i].is_honeypot = 0;
    l->nodes[i].route_prev[0] = '\0';
    l->nodes[i].is_watched   = 0;
    l->nodes[i].has_logs     = 0;
    l->nodes[i].trip_seconds = 0;
    l->nodes[i].knock_seq[0] = '\0';
    l->nodes[i].su_pass[0]   = '\0';
    l->nodes[i].link_from[0] = '\0';
    l->nodes[i].watch_slot   = 0;
    l->nodes[i].knock_window = 0;
}

/* Act V markers for the most recently added node / file. */
static void set_su(Level *l, const char *pw) { strncpy(l->nodes[l->node_count - 1].su_pass, pw, 31); }
static void set_link(Level *l, const char *hosts) { strncpy(l->nodes[l->node_count - 1].link_from, hosts, 95); }
static void set_slot(Level *l, int slot) { l->nodes[l->node_count - 1].watch_slot = slot; }
static void set_window(Level *l, int cmds) { l->nodes[l->node_count - 1].knock_window = cmds; }
static GameFile *last_file(Level *l, int n) { return &l->nodes[n].files[l->nodes[n].file_count - 1]; }

/* Mechanic markers for the most recently added node (levels 26-35). */
static void mark_watched(Level *l) { l->nodes[l->node_count - 1].is_watched = 1; }
static void mark_logs(Level *l)    { l->nodes[l->node_count - 1].has_logs   = 1; }
static void set_trip(Level *l, int secs) { l->nodes[l->node_count - 1].trip_seconds = secs; }
static void set_knock(Level *l, const char *seq) {
    strncpy(l->nodes[l->node_count - 1].knock_seq, seq, 47);
}

/* Marks the most-recently added node as a honeypot (heavy detection on connect). */
static void mark_honeypot(Level *l) {
    if (l->node_count > 0) l->nodes[l->node_count - 1].is_honeypot = 1;
}

/* Marks the most-recently added node as requiring a prior connection to 'prev_host'. */
static void route_after(Level *l, const char *prev_host) {
    if (l->node_count > 0)
        strncpy(l->nodes[l->node_count - 1].route_prev, prev_host, MAX_NODE_NAME - 1);
}

/* Appends a file to a specific node's file list. All file attributes are set
   here; the content field stores the raw (possibly encoded) text that the
   decrypt command will later decode into a temporary buffer. */
static void add_file(Level *l, int node_idx,
                     const char *name, const char *content,
                     Permission min_perm, int hidden,
                     int encrypted, int puzzle_type, int cipher_shift,
                     int locked) {
    NetworkNode *n = &l->nodes[node_idx];
    int i = n->file_count++;
    strncpy(n->files[i].name,        name,    MAX_FILENAME - 1);
    strncpy(n->files[i].content,     content, MAX_CONTENT  - 1);
    n->files[i].min_perm     = min_perm;
    n->files[i].hidden       = hidden;
    n->files[i].encrypted    = encrypted;
    n->files[i].puzzle_type  = puzzle_type;
    n->files[i].cipher_shift = cipher_shift;
    n->files[i].locked       = locked;
    n->files[i].cipher_key[0]= '\0';
    n->files[i].unlock_code[0]= '\0';
    n->files[i].manual_key   = 0;
    n->files[i].needs_root   = 0;
}

/* Variant that also stores a cipher key (used by XOR and Vigenère puzzles). */
static void add_file_keyed(Level *l, int node_idx,
                           const char *name, const char *content,
                           Permission min_perm, int hidden,
                           int puzzle_type, const char *key, int locked) {
    add_file(l, node_idx, name, content, min_perm, hidden, 1, puzzle_type, 0, locked);
    NetworkNode *n = &l->nodes[node_idx];
    int i = n->file_count - 1;
    strncpy(n->files[i].cipher_key, key ? key : "", 63);
}

/* Fully general file constructor used by the later levels: any puzzle type,
   optional key/layer spec, optional lock, and optional keypad code. */
static void add_file_full(Level *l, int node_idx, const char *name, const char *content,
                          int hidden, int puzzle_type, int shift, const char *key,
                          int locked, const char *pin) {
    add_file(l, node_idx, name, content, PERM_GUEST, hidden,
             puzzle_type != PUZZLE_NONE, puzzle_type, shift, locked);
    GameFile *f = &l->nodes[node_idx].files[l->nodes[node_idx].file_count - 1];
    strncpy(f->cipher_key,  key ? key : "", 63);
    strncpy(f->unlock_code, pin ? pin : "", 15);
}

/* Shorthand aliases used inside every init_levelN function.
   PUB/USR alias the permission enum values for brevity.
   Each macro encodes a specific combination of visibility, encryption type,
   and lock state — see README.md for the full macro reference table. */
#define PUB PERM_GUEST
#define USR PERM_USER
#define F(nm,ct)             add_file(l,n,nm,ct,PUB,0,0,PUZZLE_NONE,  0, 0)  /* plain, public              */
#define FH(nm,ct)            add_file(l,n,nm,ct,PUB,1,0,PUZZLE_NONE,  0, 0)  /* hidden (ls -a only)        */
#define FL(nm,ct)            add_file(l,n,nm,ct,PUB,0,0,PUZZLE_NONE,  0, 1)  /* locked until condition met */
#define FHL(nm,ct)           add_file(l,n,nm,ct,PUB,1,0,PUZZLE_NONE,  0, 1)  /* hidden + locked            */
#define FU(nm,ct)            add_file(l,n,nm,ct,USR,0,0,PUZZLE_NONE,  0, 0)  /* USER access required       */
#define FC(nm,ct,sh)         add_file(l,n,nm,ct,PUB,0,1,PUZZLE_CAESAR,sh, 0) /* Caesar cipher              */
#define FUC(nm,ct,sh)        add_file(l,n,nm,ct,USR,0,1,PUZZLE_CAESAR,sh, 0) /* Caesar, USER required      */
#define FR(nm,ct)            add_file(l,n,nm,ct,PUB,0,1,PUZZLE_REVERSE,0, 0) /* reverse text               */
#define FLR(nm,ct)           add_file(l,n,nm,ct,PUB,0,1,PUZZLE_REVERSE,0, 1) /* reverse text + locked      */
#define FB(nm,ct)            add_file(l,n,nm,ct,PUB,0,1,PUZZLE_BINARY, 0, 0) /* binary-to-ASCII            */
#define FX(nm,ct)            add_file(l,n,nm,ct,PUB,0,1,PUZZLE_HEX,    0, 0) /* hex-to-ASCII               */
#define FB64(nm,ct)          add_file(l,n,nm,ct,PUB,0,1,PUZZLE_BASE64, 0, 0) /* base64                     */
#define FXOR(nm,ct,k)        add_file_keyed(l,n,nm,ct,PUB,0,PUZZLE_XOR,    k, 0) /* XOR cipher              */
#define FVIG(nm,ct,k)        add_file_keyed(l,n,nm,ct,PUB,0,PUZZLE_VIGENERE,k, 0) /* Vigenère cipher        */
#define FUVIG(nm,ct,k)       add_file_keyed(l,n,nm,ct,USR,0,PUZZLE_VIGENERE,k, 0) /* Vigenère, USER         */
#define FHLB(nm,ct)          add_file(l,n,nm,ct,PUB,1,1,PUZZLE_BINARY, 0, 1) /* hidden+locked binary       */
#define FHLR(nm,ct)          add_file(l,n,nm,ct,PUB,1,1,PUZZLE_REVERSE,0, 1) /* hidden+locked reverse      */
#define FHLXOR(nm,ct,k)      add_file_keyed(l,n,nm,ct,PUB,1,PUZZLE_XOR,    k, 1) /* hidden+locked XOR       */
#define FLB64(nm,ct)         add_file(l,n,nm,ct,PUB,0,1,PUZZLE_BASE64, 0, 1) /* locked base64              */
#define FLX(nm,ct)           add_file(l,n,nm,ct,PUB,0,1,PUZZLE_HEX,    0, 1) /* locked hex                 */
/* Levels 26-35 */
#define FAT(nm,ct)           add_file_full(l,n,nm,ct,0,PUZZLE_ATBASH,0,NULL,0,NULL)  /* Atbash            */
#define FRL(nm,ct,r)         add_file_full(l,n,nm,ct,0,PUZZLE_RAIL,  r,NULL,0,NULL)  /* rail fence        */
#define FON(nm,ct,spec)      add_file_full(l,n,nm,ct,0,PUZZLE_ONION, 0,spec,0,NULL)  /* onion layers      */
#define FPIN(nm,ct,t,sh,k,pin) add_file_full(l,n,nm,ct,0,t,sh,k,1,pin)               /* keypad-locked     */
#define FLOCK(nm,ct,t,sh,k)  add_file_full(l,n,nm,ct,0,t,sh,k,1,NULL)                /* bruteforce-locked */
#define FHLOCK(nm,ct,t,sh,k) add_file_full(l,n,nm,ct,1,t,sh,k,1,NULL)                /* hidden + locked   */

/* Level 0 — Tutorial System (EASY)
   A single-node sandbox with no puzzles, no timer, and a generous detection
   budget. The password appears in a plain log file and in a hidden bash
   history file. Goal: introduce ls, cat, ls -a, and login. */
static void init_level0(void) {
    Level *l = &levels[0];
    memset(l, 0, sizeof(*l));
    l->id = 0;
    strncpy(l->name,     "Tutorial System",                  MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "EASY",                           15);
    strncpy(l->objective,
        "You have shell access to an unknown local machine.\n"
        "Explore the filesystem, read the files, and find\n"
        "the login password to proceed to your first real target.", 511);
    strncpy(l->warnings,          "None — training environment.", 255);
    strncpy(l->solution_password, "beginner",    63);
    strncpy(l->user_password,     "",            63);
    strncpy(l->hint,
        "HINT: The password describes someone new or inexperienced.\n"
        "Think of an 8-letter word meaning novice or newcomer.\n"
        "Also try: ls -a  to reveal all files.", MAX_HINT - 1);
    l->max_attempts      = 6;
    l->detection_max     = 100;
    l->detection_per_fail = 10;
    l->has_timer         = 0;
    l->available_cmds    = CMD_BASIC | CMD_HINT | CMD_LOGIN
                         | CMD_SAVEGAME | CMD_LOADGAME;

    int n = 0;
    add_node(l, "192.168.1.1", "tutorial-pc",
             "Training environment — safe for practice.", PUB, 1);

    F("welcome.txt",
        "Welcome to Terminal Breach Training v2.0.\n"
        "This machine is your first target.\n"
        "Use 'ls' to list files, 'cat <file>' to read them.\n"
        "Use 'login <password>' once you find credentials.\n"
        "New commands unlock as you advance through levels.\n");

    F("readme.txt",
        "SYSTEM MANUAL — Tutorial Node\n"
        "This machine uses default credentials.\n"
        "The password is a common English word:\n"
        "  - 8 letters long\n"
        "  - Describes someone new to a skill or field\n"
        "  - Synonym for novice or newcomer\n");

    F("system.log",
        "[BOOT] System started.\n"
        "[AUTH] User: guest  --  Access level: BEGINNER\n"
        "[INFO] Default account type: beginner\n"
        "[WARN] Change default password after first login.\n");

    FH(".bash_history",
        "ls\n"
        "cat readme.txt\n"
        "login beginner\n"
        "exit\n");
}

/* Level 1 — Employee PC (EASY)
   Introduces the decrypt command via a reverse-text puzzle. The password
   is also visible in a hidden notes file as a safety net. Goal: teach
   the decrypt/save/inventory workflow before multi-node levels. */
static void init_level1(void) {
    Level *l = &levels[1];
    memset(l, 0, sizeof(*l));
    l->id = 1;
    strncpy(l->name,     "Employee PC",                      MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "EASY",                           15);
    strncpy(l->objective,
        "Target: Jamie Chen's personal workstation (10.0.0.42).\n"
        "IT stored the project access code in an encoded file.\n"
        "Decode it and login.\n"
        "New tools: decrypt, save, inventory.", 511);
    strncpy(l->warnings,          "Low security — standard detection.", 255);
    strncpy(l->solution_password, "Sp3ctrum_42", 63);
    strncpy(l->user_password,     "",            63);
    strncpy(l->hint,
        "HINT: There is an encoded file: message.enc.\n"
        "Use 'decrypt message.enc' to decode reverse-text.\n"
        "Also try 'ls -a' to see hidden files.", MAX_HINT - 1);
    l->max_attempts      = 5;
    l->detection_max     = 80;
    l->detection_per_fail = 15;
    l->has_timer         = 0;
    l->available_cmds    = CMD_BASIC | CMD_HINT | CMD_LOGIN | CMD_LOGOUT
                         | CMD_DECRYPT | CMD_SAVE | CMD_INVENTORY
                         | CMD_SAVEGAME | CMD_LOADGAME;

    int n = 0;
    add_node(l, "10.0.0.42", "jamie-pc",
             "Jamie Chen's personal workstation.", PUB, 1);

    F("readme.txt",
        "Jamie Chen's personal workstation.\n"
        "Do not access without written authorisation.\n");

    F("inbox.txt",
        "From: IT Support <it@corp.net>\n"
        "To  : jamie@corp.net\n"
        "\n"
        "Jamie, your project access code is stored in\n"
        "message.enc. Use the decrypt tool to read it.\n"
        "                            -IT Dept\n");

    F("about.txt",
        "Employee   : Jamie Chen\n"
        "Department : R&D\n"
        "Project    : Spectrum\n"
        "Employee ID: JC-042\n");

    /* REVERSE puzzle
       Plaintext : "Hi Jamie. Your password is the project code: Sp3ctrum_42."
       Reversed  : ".24_murtc3pS :edoc tcejorp eht si drowssap ruoY .eimaJ iH" */
    FR("message.enc",
        ".24_murtc3pS :edoc tcejorp eht si drowssap ruoY .eimaJ iH");

    FH(".hidden_notes",
        "Quick ref -- DO NOT LEAVE ON DESKTOP\n"
        "pw = Sp3ctrum_42  (project Spectrum access)\n");
}

/* Level 2 — Office Server (MEDIUM)
   First multi-node level. Introduces the user password tier, scan, and
   connect. The HR server is only reachable after gaining USER access.
   Caesar-13 (ROT-13) is the cipher — the shift is disclosed in a plain file. */
static void init_level2(void) {
    Level *l = &levels[2];
    memset(l, 0, sizeof(*l));
    l->id = 2;
    strncpy(l->name,     "Office Server",                    MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "MEDIUM",                         15);
    strncpy(l->objective,
        "Target: Thornfield Corp office server (172.16.0.10).\n"
        "Staff credentials unlock more files and nodes.\n"
        "Multi-step: login staff -> scan -> connect hr-server\n"
        "-> decrypt config_backup.enc -> login with found code.", 511);
    strncpy(l->warnings,          "Permission system active.", 255);
    strncpy(l->solution_password, "0ff1c3_@dm1n", 63);
    strncpy(l->user_password,     "staff_2024",   63);
    strncpy(l->hint,
        "HINT: Staff password format is [role]_[year].\n"
        "Role: staff. Year: 2024.\n"
        "After user login, scan for hr-server (172.16.0.20).\n"
        "Decrypt config_backup.enc — cipher shift is 13.", MAX_HINT - 1);
    l->max_attempts      = 6;
    l->detection_max     = 70;
    l->detection_per_fail = 20;
    l->has_timer         = 0;
    l->available_cmds    = CMD_BASIC | CMD_HINT | CMD_LOGIN | CMD_LOGOUT
                         | CMD_DECRYPT | CMD_SAVE | CMD_INVENTORY
                         | CMD_SCAN    | CMD_CONNECT
                         | CMD_SAVEGAME | CMD_LOADGAME;

    /* Node 0: office-srv (entry) */
    int n = 0;
    add_node(l, "172.16.0.10", "office-srv",
             "Thornfield Corp main office server.", PUB, 1);

    F("notice.txt",
        "RESTRICTED -- Thornfield Corp Office Server\n"
        "Staff credentials required for full file access.\n"
        "Use: login <password>\n");

    F("staff_memo.txt",
        "Staff credentials follow the format: [role]_[year]\n"
        "Default role: staff\n"
        "Active directory year: 2024\n"
        "Contact IT if you have login issues.\n");

    FU("network_info.txt",
        "HR subsystem located at 172.16.0.20.\n"
        "Run 'scan' to confirm connectivity.\n"
        "HR server holds encrypted configuration backups.\n");

    F("system_info.txt",
        "OS: CorpOS 3.1  |  Uptime: 847 days\n"
        "Firewall: ACTIVE  |  IDS: ACTIVE\n"
        "Encryption standard: ROT-13 (legacy corporate policy)\n");

    /* Node 1: hr-server (requires USER to connect) */
    n = 1;
    add_node(l, "172.16.0.20", "hr-server",
             "HR subsystem -- employee records and config backups.", USR, 0);

    F("hr_welcome.txt",
        "HR SYSTEM -- Thornfield Corp\n"
        "Employee records and admin configs stored here.\n"
        "Encrypted backups follow the standard office cipher.\n");

    F("cipher_info.txt",
        "SECURITY POLICY:\n"
        "All config backups encrypted with Caesar shift 13.\n"
        "(ROT-13 standard). Apply this shift when decrypting.\n");

    /* CAESAR-13 puzzle
       Plaintext : "Root auth code: 0ff1c3_@dm1n"
       Encrypted : "Ebbg nhgu pbqr: 0ss1p3_@qz1a" */
    FC("config_backup.enc", "Ebbg nhgu pbqr: 0ss1p3_@qz1a", 13);

    F("employee_records.txt",
        "EMPLOYEE RECORDS (REDACTED)\n"
        "Total staff     : 47\n"
        "Admin accounts  : 3\n"
        "Last audit      : 2024-01-15\n"
        "[Full records require admin authentication]\n");
}

/* Level 3 — Bank Network (MEDIUM)
   Reinforces the scan/connect/decrypt workflow with tighter detection.
   The cipher shift (7) is in a dedicated key file on the vault node,
   establishing the pattern of reading one file to decode another. */
static void init_level3(void) {
    Level *l = &levels[3];
    memset(l, 0, sizeof(*l));
    l->id = 3;
    strncpy(l->name,     "Bank Network",                     MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "MEDIUM",                         15);
    strncpy(l->objective,
        "Target: Iron Bank financial systems (10.10.0.1).\n"
        "The vault master code is encrypted on the vault node.\n"
        "Break in: login as employee -> scan -> connect\n"
        "vault-server -> decrypt vault.enc -> login.", 511);
    strncpy(l->warnings,          "HIGH SECURITY -- all sessions logged.", 255);
    strncpy(l->solution_password, "$Bank_M@ster99", 63);
    strncpy(l->user_password,     "staff_access",   63);
    strncpy(l->hint,
        "HINT: Default bank employee password is 'staff_access'.\n"
        "After login, scan and connect to vault-server (10.10.0.5).\n"
        "Check cipher_key.txt for the shift value.\n"
        "Decrypt vault.enc then login with the decoded code.", MAX_HINT - 1);
    l->max_attempts      = 5;
    l->detection_max     = 60;
    l->detection_per_fail = 25;
    l->has_timer         = 0;
    l->available_cmds    = CMD_BASIC | CMD_HINT | CMD_LOGIN | CMD_LOGOUT
                         | CMD_DECRYPT | CMD_SAVE | CMD_INVENTORY
                         | CMD_SCAN    | CMD_CONNECT
                         | CMD_SAVEGAME | CMD_LOADGAME;

    /* Node 0: bank-gateway (entry) */
    int n = 0;
    add_node(l, "10.10.0.1", "bank-gateway",
             "Iron Bank entry gateway.", PUB, 1);

    F("security_notice.txt",
        "IRON BANK FINANCIAL SYSTEMS\n"
        "HIGH SECURITY ZONE -- All access is logged.\n"
        "Unauthorised access is a federal offense.\n");

    F("access_info.txt",
        "Bank employee default credentials:\n"
        "  Password : staff_access\n"
        "Change your password after first login.\n");

    FU("network_map.txt",
        "Internal network -- 10.10.0.x segment:\n"
        "  10.10.0.1  -- gateway (current)\n"
        "  10.10.0.5  -- vault subsystem (RESTRICTED)\n"
        "Run 'scan' to discover live hosts.\n");

    F("audit.log",
        "[2024-03-15 03:22] Failed login from 10.10.0.88\n"
        "[2024-03-15 03:24] Port scan detected from external\n"
        "[2024-03-15 03:25] Alert: probe attempt on vault-server\n"
        "[2024-03-15 03:26] vault-server cipher rotation logged\n");

    /* Node 1: vault-server (requires USER) */
    n = 1;
    add_node(l, "10.10.0.5", "vault-server",
             "Vault subsystem -- restricted access.", USR, 0);

    F("vault_readme.txt",
        "VAULT SUBSYSTEM -- Iron Bank\n"
        "Master authentication required for vault access.\n"
        "Authentication code stored in vault.enc (encrypted).\n");

    F("cipher_key.txt",
        "Vault encryption protocol: ROT-7\n"
        "Apply shift value of 7 when using the decrypt tool.\n");

    /* CAESAR-7 puzzle
       Plaintext : "master_code: $Bank_M@ster99"
       Encrypted : "thzaly_jvkl: $Ibur_T@zaly99" */
    FC("vault.enc", "thzaly_jvkl: $Ihur_T@zaly99", 7);

    F("access_log.txt",
        "[VAULT] Last access : 2024-01-08 by vault_admin\n"
        "[VAULT] Master code : CHANGED 2024-01-08\n"
        "[VAULT] Status      : LOCKED -- master auth required\n");
}

/* Level 4 — Secure Vault (HARD)
   Introduces bruteforce and the binary puzzle type. The password is
   assembled from two independent sources: the bruteforce-unlocked prefix
   and the binary-decoded suffix. A 300-second timer adds time pressure.
   Single node — complexity comes from combining two puzzle types, not navigation. */
static void init_level4(void) {
    Level *l = &levels[4];
    memset(l, 0, sizeof(*l));
    l->id = 4;
    strncpy(l->name,     "Secure Vault",                     MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "HARD",                           15);
    strncpy(l->objective,
        "Target: High-security vault system (192.168.99.1).\n"
        "Timer active. Detection is extremely sensitive.\n"
        "Use bruteforce to unlock a partial key, decode the\n"
        "binary memory dump, and combine both for the password.", 511);
    strncpy(l->warnings,
        "TIMED (300s) | EXTREME DETECTION SENSITIVITY", 255);
    strncpy(l->solution_password, "V@ULT_K3Y_7749", 63);
    strncpy(l->user_password,     "",               63);
    strncpy(l->hint,
        "HINT: Use 'bruteforce' to partially bypass the lock.\n"
        "Then 'decrypt system_dump.bin' to decode binary data.\n"
        "Combine the vault prefix with the decoded 4-digit code.", MAX_HINT - 1);
    l->max_attempts      = 4;
    l->detection_max     = 50;
    l->detection_per_fail = 12;
    l->has_timer         = 1;
    l->timer_seconds     = 300;
    l->available_cmds    = CMD_BASIC | CMD_HINT | CMD_LOGIN | CMD_LOGOUT
                         | CMD_DECRYPT | CMD_SAVE | CMD_INVENTORY
                         | CMD_SCAN    | CMD_CONNECT
                         | CMD_BRUTEFORCE
                         | CMD_SAVEGAME | CMD_LOADGAME;

    int n = 0;
    add_node(l, "192.168.99.1", "vault-entry",
             "High-security vault entry point.", PUB, 1);

    F("warning.txt",
        "SECURE FACILITY ALERT\n"
        "Timer activated -- 300 seconds maximum session time.\n"
        "Detection system at MAXIMUM sensitivity.\n"
        "Intrusion countermeasures are live.\n");

    F("keypad.txt",
        "Vault lock format: [PREFIX]_K3Y_[4 digits]\n"
        "The prefix contains a special character (@).\n"
        "Use bruteforce to reveal the prefix.\n"
        "Decode system_dump.bin to find the 4-digit suffix.\n");

    /* BINARY puzzle
       Encodes  : "7749"
       Binary   : 00110111 00110111 00110100 00111001 */
    FB("system_dump.bin",
        "00110111 00110111 00110100 00111001");

    /* Locked until bruteforce is used */
    FL("vault_access.txt",
        "PARTIAL BREACH -- authentication subsystem bypassed.\n"
        "Vault lock prefix recovered: V@ULT_K3Y_\n"
        "Combine with the 4-digit suffix from system_dump.bin.\n");
}

/* Level 5 — Darknet Node (HARD)
   Extreme detection sensitivity: at 35 per-fail on a 40 max, a single wrong
   login leaves the player with 5 detection remaining. The solution path is
   straightforward — the difficulty is entirely about executing without errors.
   Teaches the player to read all files carefully before attempting login. */
static void init_level5(void) {
    Level *l = &levels[5];
    memset(l, 0, sizeof(*l));
    l->id = 5;
    strncpy(l->name,     "Darknet Node",                     MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "HARD",                           15);
    strncpy(l->objective,
        "Target: Anonymous darknet relay (10.13.37.1).\n"
        "Base credentials are left in the welcome file.\n"
        "Elevate to user access, find the cipher key, and\n"
        "decrypt the manifesto to retrieve the passphrase.", 511);
    strncpy(l->warnings,
        "MAXIMUM DETECTION SENSITIVITY | 3 fails = lockout", 255);
    strncpy(l->solution_password, "d4rkn3t_gh0st", 63);
    strncpy(l->user_password,     "anon_user",     63);
    strncpy(l->hint,
        "HINT: Base credentials are in welcome.onion.\n"
        "Login to get user access, read darknet_key.txt.\n"
        "Shift for encrypted_manifesto.enc is 17.", MAX_HINT - 1);
    l->max_attempts      = 4;
    l->detection_max     = 40;
    l->detection_per_fail = 35;
    l->has_timer         = 0;
    l->available_cmds    = CMD_BASIC | CMD_HINT | CMD_LOGIN | CMD_LOGOUT
                         | CMD_DECRYPT | CMD_SAVE | CMD_INVENTORY
                         | CMD_SCAN    | CMD_CONNECT
                         | CMD_BRUTEFORCE
                         | CMD_SAVEGAME | CMD_LOADGAME;

    int n = 0;
    add_node(l, "10.13.37.1", "darknet-node",
             "Anonymous darknet relay -- identity unknown.", PUB, 1);

    F("welcome.onion",
        "Welcome to the darknet relay.\n"
        "This node routes traffic for anonymous operations.\n"
        "Base authentication credentials: anon_user\n"
        "[Warning: 3 failed logins triggers permanent lockout]\n");

    FU("darknet_key.txt",
        "Darknet cipher protocol: Caesar shift = 17\n"
        "All encrypted communications on this relay use\n"
        "this offset. Apply when using the decrypt tool.\n");

    /* CAESAR-17 puzzle
       Plaintext : "The ghost protocol: d4rkn3t_gh0st"
       Encrypted : "Kyv xyfjk gifkftfc: u4ibe3k_xy0jk" */
    FUC("encrypted_manifesto.enc",
        "Kyv xyfjk gifkftfc: u4ibe3k_xy0jk", 17);

    F("access_log.txt",
        "[10.13.37.1] Session opened\n"
        "[10.13.37.1] Auth required for sensitive files\n"
        "[10.13.37.1] Warning: 3 failures triggers lockout\n");
}

/* Level 6 — Prometheus Military Grid (HARD)
   Introduces connect side-effects: connecting to firebase automatically
   unlocks classified.txt on that node. The override command is made available
   here but is not required — it is introduced so the player knows it exists
   before it becomes mandatory in later levels. Three nodes, no user password. */
static void init_level6(void) {
    Level *l = &levels[6];
    memset(l, 0, sizeof(*l));
    l->id = 6;
    strncpy(l->name,     "Prometheus Military Grid",         MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "HARD",                           15);
    strncpy(l->objective,
        "CLASSIFIED -- EYES ONLY.\n"
        "Target: Prometheus military command grid.\n"
        "Disable the warhead control before launch window.\n"
        "Scan -> connect firebase -> decrypt orders.enc ->\n"
        "connect warhead-ctrl -> login to neutralise.", 511);
    strncpy(l->warnings,
        "OMEGA CLEARANCE | EXTREME DETECTION | 3 ATTEMPTS MAX", 255);
    strncpy(l->solution_password, "ZEPHYR-7-ECHO", 63);
    strncpy(l->user_password,     "",              63);
    strncpy(l->hint,
        "HINT: Scan first, then connect to firebase.\n"
        "Connecting to firebase unlocks classified.txt.\n"
        "Cipher shift for orders.enc is 3.\n"
        "Then connect warhead-ctrl and login.", MAX_HINT - 1);
    l->max_attempts      = 3;
    l->detection_max     = 60;
    l->detection_per_fail = 20;
    l->has_timer         = 0;
    l->available_cmds    = CMD_BASIC | CMD_HINT | CMD_LOGIN | CMD_LOGOUT
                         | CMD_DECRYPT | CMD_SAVE | CMD_INVENTORY
                         | CMD_SCAN    | CMD_CONNECT
                         | CMD_BRUTEFORCE | CMD_OVERRIDE
                         | CMD_SAVEGAME  | CMD_LOADGAME;

    /* Node 0: prometheus entry */
    int n = 0;
    add_node(l, "10.200.0.1", "prometheus",
             "Prometheus military command grid -- entry.", PUB, 1);

    F("access_levels.txt",
        "CLEARANCE REQUIRED: OMEGA\n"
        "Node firebase     : accessible -- scan to discover\n"
        "Node warhead-ctrl : restricted -- accessible after\n"
        "                    connecting to firebase first.\n"
        "Authentication    : operation codename-based\n");

    F("personnel.txt",
        "Commander Ridge   -- OMEGA clearance\n"
        "Lt. Vasquez       -- DELTA clearance\n"
        "Dr. Chen          -- SIGMA clearance (weapons div)\n"
        "Codename format   : [WORD]-[DIGIT]-[NATO phonetic]\n");

    /* Node 1: firebase (scan-discoverable) */
    n = 1;
    add_node(l, "10.200.0.5", "firebase",
             "Forward military base -- communications relay.", PUB, 0);

    /* classified.txt locked until firebase is connected (unlocked by cmd_connect) */
    FL("classified.txt",
        "OPERATION BLACKOUT -- LAUNCH OVERRIDE PROTOCOL\n"
        "Step 1: Connect to firebase node\n"
        "Step 2: Decrypt orders.enc  (Caesar shift: 3)\n"
        "Step 3: Connect to warhead-ctrl\n"
        "Step 4: Enter decoded codename as password\n"
        "Codename format: [WORD]-[DIGIT]-[NATO phonetic]\n");

    /* CAESAR-3 puzzle
       Plaintext : "ZEPHYR-7-ECHO"
       Encrypted : "CHSKBU-7-HFKR"
       Z+3=C, E+3=H, P+3=S, H+3=K, Y+3=B, R+3=U | E+3=H, C+3=F, H+3=K, O+3=R */
    FC("orders.enc", "CHSKBU-7-HFKR", 3);

    /* Node 2: warhead-ctrl (scan-discoverable) */
    n = 2;
    add_node(l, "10.200.0.99", "warhead-ctrl",
             "Warhead control system -- OMEGA clearance required.", PUB, 0);

    F("system_status.txt",
        "WARHEAD CONTROL -- ONLINE\n"
        "Launch window: T-minus 00:47:00\n"
        "Authentication: ACTIVE\n"
        "Enter operation codename to abort launch sequence.\n");
}

/* Level 7 — AI Core System (EXTREME)
   The original final level. Three-fragment password assembly requiring binary
   decode, Caesar-9 decrypt, and override (which costs 90 of 100 detection).
   The override is unavoidable, leaving no margin for a login mistake afterward.
   A 180-second timer keeps pressure high throughout the multi-step sequence. */
static void init_level7(void) {
    Level *l = &levels[7];
    memset(l, 0, sizeof(*l));
    l->id = 7;
    strncpy(l->name,     "AI Core System",                   MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "EXTREME",                        15);
    strncpy(l->objective,
        "FINAL TARGET: AI Core neural processing system.\n"
        "Three password fragments are scattered across nodes.\n"
        "Fragment 1: decode binary.sys\n"
        "Fragment 2: Caesar cipher on neural-net node\n"
        "Fragment 3: hidden file -- use override\n"
        "Combine all three and login to WIN.", 511);
    strncpy(l->warnings,
        "TIMED (180s) | EXTREME DETECTION | FINAL LEVEL", 255);
    strncpy(l->solution_password, "NEURAL_0VERRIDE_7", 63);
    strncpy(l->user_password,     "AI_Guest01",        63);
    strncpy(l->hint,
        "HINT: Start by decoding binary.sys to get NEURAL_.\n"
        "Login as AI_Guest01, scan, connect to neural-net.\n"
        "Decrypt cipher_fragment.enc (shift 9) to get 0VERRIDE_.\n"
        "Use override to unlock .genesis_key (fragment: 7).\n"
        "Full password: NEURAL_0VERRIDE_7", MAX_HINT - 1);
    l->max_attempts      = 3;
    l->detection_max     = 100;
    l->detection_per_fail = 30;
    l->has_timer         = 1;
    l->timer_seconds     = 180;
    l->available_cmds    = CMD_BASIC | CMD_HINT | CMD_LOGIN | CMD_LOGOUT
                         | CMD_DECRYPT | CMD_SAVE | CMD_INVENTORY
                         | CMD_SCAN    | CMD_CONNECT
                         | CMD_BRUTEFORCE | CMD_OVERRIDE
                         | CMD_SAVEGAME  | CMD_LOADGAME;

    /* Node 0: ai-core (entry) */
    int n = 0;
    add_node(l, "10.0.0.1", "ai-core",
             "AI Core central processing node.", PUB, 1);

    F("ai_boot.txt",
        "AI CORE SYSTEM -- CLASSIFIED\n"
        "Neural processing units : ONLINE\n"
        "Security level          : OMEGA\n"
        "Base authentication     : AI_Guest01\n"
        "[WARNING: timer active, detection sensitivity MAX]\n");

    F("system_manual.txt",
        "Authentication system overview:\n"
        "  Fragment 1 -- Binary encoded in binary.sys\n"
        "  Fragment 2 -- Cipher encoded on neural-net node\n"
        "  Fragment 3 -- Hidden; requires override command\n"
        "Assemble all three fragments for the master key.\n");

    /* BINARY puzzle
       Encodes : "NEURAL_"
       Binary  : 01001110 01000101 01010101 01010010 01000001 01001100 01011111 */
    FB("binary.sys",
        "01001110 01000101 01010101 01010010 01000001 01001100 01011111");

    F("ai_warning.txt",
        "INTRUSION COUNTERMEASURES ACTIVE\n"
        "Every failed attempt increases trace probability.\n"
        "Timer running. You have been warned, GHOST.\n");

    /* Node 1: neural-net (requires USER) */
    n = 1;
    add_node(l, "10.0.0.2", "neural-net",
             "Neural network subsystem -- user access required.", USR, 0);

    F("core_manual.txt",
        "Neural cipher protocol  : Caesar shift = 9\n"
        "Authentication fragment : stored in cipher_fragment.enc\n"
        "Apply shift 9 when using the decrypt tool.\n");

    /* CAESAR-9 puzzle
       Plaintext : "0VERRIDE_"
       Encrypted : "0ENAARMN_" */
    FC("cipher_fragment.enc", "0ENAARMN_", 9);

    /* Hidden + locked -- unlocked by override command */
    FHL(".genesis_key",
        "GENESIS CORE UNLOCKED\n"
        "Override sequence successful.\n"
        "Final fragment: 7\n");

    F("ai_core_log.txt",
        "[AI] Neural pathway optimisation: complete\n"
        "[AI] Intrusion detected -- countermeasures engaged\n"
        "[AI] If you read this, the override succeeded\n"
        "[AI] Congratulations, GHOST. You found the key.\n");
}

/* Level 8 — Corporate Espionage (HARD)
   Introduces the mechanic of carrying information across nodes: the cipher
   key (shift 11) lives on records-srv while the encrypted target lives on
   archive-srv. The player must read and remember the shift before connecting
   to the node where it will be applied. Three nodes, no timer. */
static void init_level8(void) {
    Level *l = &levels[8];
    memset(l, 0, sizeof(*l));
    l->id = 8;
    strncpy(l->name,     "Corporate Espionage",               MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "HARD",                            15);
    strncpy(l->objective,
        "Target: Harrington & Reed law firm (10.50.0.1).\n"
        "They hold stolen biotech IP for a criminal client.\n"
        "The project codename unlocks their sealed archive.\n"
        "The cipher key is NOT on the same node as the file.", 511);
    strncpy(l->warnings,  "Multi-node -- read carefully before you decrypt.", 255);
    strncpy(l->solution_password, "HELIOS_GENESIS", 63);
    strncpy(l->user_password,     "h&r_staff",      63);
    strncpy(l->hint,
        "HINT: Staff accounts follow the format h&r_[role].\n"
        "Role 'staff' is listed in staff_directory.txt.\n"
        "Cipher shift 11 is on records-srv, not archive-srv.\n"
        "Decrypt project_code.enc on archive-srv to win.", MAX_HINT - 1);
    l->max_attempts       = 5;
    l->detection_max      = 55;
    l->detection_per_fail = 18;
    l->has_timer          = 0;
    l->available_cmds     = CMD_BASIC | CMD_HINT | CMD_LOGIN | CMD_LOGOUT
                          | CMD_DECRYPT | CMD_SAVE | CMD_INVENTORY
                          | CMD_SCAN    | CMD_CONNECT
                          | CMD_BRUTEFORCE | CMD_OVERRIDE
                          | CMD_SAVEGAME   | CMD_LOADGAME;

    /* Node 0: firm-gateway (entry) */
    int n = 0;
    add_node(l, "10.50.0.1", "firm-gateway",
             "Harrington & Reed -- public reception gateway.", PUB, 1);

    F("reception.txt",
        "HARRINGTON & REED -- LAW FIRM\n"
        "Welcome to the client portal.\n"
        "Staff accounts follow the format: h&r_[role]\n"
        "Contact reception for access queries.\n");

    F("staff_directory.txt",
        "STAFF DIRECTORY (partial)\n"
        "Partner     : harrington\n"
        "Partner     : reed\n"
        "Senior      : senior_assoc\n"
        "Staff       : staff\n"
        "IT Support  : it_support\n");

    FU("it_ticket.txt",
        "IT TICKET #0042\n"
        "Reminder: all archive backups use Caesar shift 11\n"
        "per firm security policy. Do not change without\n"
        "authorisation from the managing partner.\n");

    FU("network_layout.txt",
        "INTERNAL NETWORK -- 10.50.0.x\n"
        "  10.50.0.1   firm-gateway  (current)\n"
        "  10.50.0.10  records-srv   (case records)\n"
        "  10.50.0.25  archive-srv   (sealed case archive)\n");

    /* Node 1: records-srv (requires USER) */
    n = 1;
    add_node(l, "10.50.0.10", "records-srv",
             "Case records server -- active matters.", USR, 0);

    F("case_index.txt",
        "ACTIVE CASE REGISTRY\n"
        "Client        : BioNova Corp\n"
        "Matter        : IP misappropriation defence\n"
        "Project code  : HELIOS (details sealed)\n"
        "Status        : Active -- archive sealed\n");

    F("cipher_protocol.txt",
        "DOCUMENT SECURITY PROTOCOL\n"
        "Sensitive documents use Caesar shift 11.\n"
        "Applied to all .enc files in the sealed archive.\n"
        "Key rotates annually; current key: shift 11.\n");

    FU("bionova_brief.txt",
        "BIONOVA CORP -- CASE BACKGROUND\n"
        "Client alleges theft of proprietary biotech research.\n"
        "Stolen IP codename stored encrypted in archive-srv.\n"
        "Codename begins with the project identifier HELIOS.\n");

    /* Node 2: archive-srv (requires USER) */
    n = 2;
    add_node(l, "10.50.0.25", "archive-srv",
             "Sealed case archive -- restricted access.", USR, 0);

    F("archive_readme.txt",
        "SEALED CASE ARCHIVE\n"
        "Archived case files are encrypted per firm policy.\n"
        "Use the firm cipher (see records-srv) to decrypt.\n"
        "Unauthorised access is a criminal offence.\n");

    /* CAESAR-11 puzzle
       Plaintext : HELIOS_GENESIS
       Encoded   : SPWTZD_RPYPDTD */
    FC("project_code.enc", "SPWTZD_RPYPDTD", 11);

    FU("bionova_contract.txt",
        "BIONOVA CORP -- RETAINER AGREEMENT\n"
        "Project codename: HELIOS_GENESIS\n"
        "Classification: SEALED -- partner eyes only\n"
        "This file confirms the stolen IP project codename.\n");
}

/* Level 9 — Power Grid Control (HARD)
   First 4-node level. The override code is assembled from two separate decoded
   fragments: a Caesar-6 word from scada-relay and a binary 2-digit suffix from
   emergency-backup. A 240-second timer enforces efficient navigation and teaches
   the player to plan their route before moving. */
static void init_level9(void) {
    Level *l = &levels[9];
    memset(l, 0, sizeof(*l));
    l->id = 9;
    strncpy(l->name,     "Power Grid Control",                MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "HARD",                            15);
    strncpy(l->objective,
        "Target: Meridian Energy SCADA system (192.168.200.1).\n"
        "A rogue process is 4 minutes from triggering a\n"
        "cascading blackout. Override code split across two\n"
        "nodes: decode Caesar fragment + binary suffix.", 511);
    strncpy(l->warnings,  "TIMED (240s) | MULTI-NODE | TWO-FRAGMENT PASSWORD", 255);
    strncpy(l->solution_password, "GRID_SIGMA_04", 63);
    strncpy(l->user_password,     "meridian_eng",  63);
    strncpy(l->hint,
        "HINT: Staff format is meridian_[role], role is 'eng'.\n"
        "On scada-relay: shift 6 decrypts grid_fragment.enc.\n"
        "On emergency-backup: decode suffix.bin (binary).\n"
        "Combine: GRID_SIGMA + _ + 04 = GRID_SIGMA_04.", MAX_HINT - 1);
    l->max_attempts       = 5;
    l->detection_max      = 50;
    l->detection_per_fail = 15;
    l->has_timer          = 1;
    l->timer_seconds      = 240;
    l->available_cmds     = CMD_BASIC | CMD_HINT | CMD_LOGIN | CMD_LOGOUT
                          | CMD_DECRYPT | CMD_SAVE | CMD_INVENTORY
                          | CMD_SCAN    | CMD_CONNECT
                          | CMD_BRUTEFORCE | CMD_OVERRIDE
                          | CMD_SAVEGAME   | CMD_LOADGAME;

    /* Node 0: meridian-hq (entry) */
    int n = 0;
    add_node(l, "192.168.200.1", "meridian-hq",
             "Meridian Energy headquarters -- entry.", PUB, 1);

    F("alert.txt",
        "MERIDIAN ENERGY -- EMERGENCY ALERT\n"
        "Rogue process detected on SCADA network.\n"
        "Cascading blackout imminent -- 4 minutes to impact.\n"
        "Override required immediately. Timer is active.\n");

    F("engineer_memo.txt",
        "STAFF ACCESS MEMO\n"
        "Engineer credentials follow the format:\n"
        "  meridian_[role]\n"
        "Default engineering role identifier: eng\n");

    FU("scada_overview.txt",
        "SCADA SUBSYSTEM MAP\n"
        "  192.168.200.10  scada-relay      (comms relay)\n"
        "  192.168.200.20  grid-ctrl        (grid control)\n"
        "  192.168.200.99  emergency-backup (backup systems)\n"
        "Override code is split across subsystem nodes.\n");

    /* Node 1: scada-relay (requires USER) */
    n = 1;
    add_node(l, "192.168.200.10", "scada-relay",
             "SCADA communications relay.", USR, 0);

    F("relay_status.txt",
        "SCADA RELAY -- LIVE STATUS\n"
        "Grid sector A: NOMINAL\n"
        "Grid sector B: ALERT -- rogue process active\n"
        "Grid sector C: NOMINAL\n"
        "Override window: closing in approximately 4 minutes\n");

    F("protocol_log.txt",
        "SCADA SECURITY PROTOCOL\n"
        "Backup cipher standard: Caesar shift 6.\n"
        "Applied across all SCADA grid nodes.\n"
        "Cipher key on file for emergency override use.\n");

    /* CAESAR-6 puzzle
       Plaintext : GRID_SIGMA
       Encoded   : MXOJ_YOMSG */
    FC("grid_fragment.enc", "MXOJ_YOMSG", 6);

    /* Node 2: grid-ctrl (requires USER) */
    n = 2;
    add_node(l, "192.168.200.20", "grid-ctrl",
             "Grid control subsystem.", USR, 0);

    F("grid_manual.txt",
        "GRID OVERRIDE FORMAT\n"
        "Emergency override format: [WORD]_[WORD]_[2 digits]\n"
        "First two words come from scada-relay fragment.\n"
        "Numeric suffix is binary-encoded on emergency-backup.\n");

    FU("override_partial.txt",
        "PARTIAL OVERRIDE NOTE\n"
        "Numeric suffix (2 digits) is stored on the\n"
        "emergency-backup node, binary encoded.\n"
        "Retrieve and append to the scada-relay fragment.\n");

    /* Node 3: emergency-backup (requires USER) */
    n = 3;
    add_node(l, "192.168.200.99", "emergency-backup",
             "Emergency backup systems.", USR, 0);

    F("backup_readme.txt",
        "EMERGENCY BACKUP NODE\n"
        "Last-resort override data stored here.\n"
        "Binary-encoded suffix for the override code.\n"
        "Decode suffix.bin and append to the grid fragment.\n");

    /* BINARY puzzle
       Encodes  : "04"
       Binary   : 00110000 00110100 */
    FB("suffix.bin", "00110000 00110100");

    F("system_log.txt",
        "[SCADA] 03:41:12 Rogue process spawned on sector B\n"
        "[SCADA] 03:41:55 Containment failed -- escalating\n"
        "[SCADA] 03:42:30 Emergency override window: 4 min\n"
        "[SCADA] 03:43:01 Operator: initiating remote breach\n");
}

/* Level 10 — Intelligence Agency (VERY HARD)
   Introduces the two-step decode chain: decrypting shift_table.enc (reverse)
   on ops-terminal reveals "Director cipher protocol: shift 19", which the
   player must then apply to mole_file.enc on director-pc. Misreading either
   output breaks the chain. Detection per-fail is 22 on a 45 max — effectively
   two wrong logins end the run. Four nodes, no timer. */
static void init_level10(void) {
    Level *l = &levels[10];
    memset(l, 0, sizeof(*l));
    l->id = 10;
    strncpy(l->name,     "Intelligence Agency",               MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "VERY HARD",                       15);
    strncpy(l->objective,
        "Target: CIPHER Bureau (172.31.0.1).\n"
        "A mole is leaking field agent identities.\n"
        "Two-step decode: first file reveals the shift\n"
        "needed to decrypt the second. Read carefully.", 511);
    strncpy(l->warnings,
        "VERY HIGH DETECTION | 4 ATTEMPTS | NO TIMER", 255);
    strncpy(l->solution_password, "MOLE_EXPOSED_11", 63);
    strncpy(l->user_password,     "analyst_delta",   63);
    strncpy(l->hint,
        "HINT: Analyst accounts: analyst_[identifier].\n"
        "Role is 'delta' per personnel_manifest.txt.\n"
        "On ops-terminal: decrypt shift_table.enc (reverse).\n"
        "The decoded text reveals the shift for mole_file.enc.", MAX_HINT - 1);
    l->max_attempts       = 4;
    l->detection_max      = 45;
    l->detection_per_fail = 22;
    l->has_timer          = 0;
    l->available_cmds     = CMD_BASIC | CMD_HINT | CMD_LOGIN | CMD_LOGOUT
                          | CMD_DECRYPT | CMD_SAVE | CMD_INVENTORY
                          | CMD_SCAN    | CMD_CONNECT
                          | CMD_BRUTEFORCE | CMD_OVERRIDE
                          | CMD_SAVEGAME   | CMD_LOADGAME;

    /* Node 0: cipher-gateway (entry) */
    int n = 0;
    add_node(l, "172.31.0.1", "cipher-gateway",
             "CIPHER Bureau -- restricted entry.", PUB, 1);

    F("security_notice.txt",
        "CIPHER BUREAU -- RESTRICTED ACCESS\n"
        "All sessions are monitored and logged.\n"
        "Analyst accounts required for classified material.\n"
        "Unauthorised access: federal criminal offence.\n");

    F("personnel_manifest.txt",
        "ANALYST ROSTER (partial)\n"
        "Credentials follow format: analyst_[identifier]\n"
        "Identifiers: alpha, bravo, charlie, DELTA, echo\n"
        "Current duty: analyst delta -- internal audit\n");

    FU("agency_memo.txt",
        "INTERNAL MEMO -- MOLE INVESTIGATION\n"
        "Mole identity confirmed. Codename on director-pc.\n"
        "Director's cipher key stored on ops-terminal.\n"
        "Records-vault holds supporting case documentation.\n");

    /* Node 1: ops-terminal (requires USER) */
    n = 1;
    add_node(l, "172.31.0.10", "ops-terminal",
             "Operations terminal -- analyst workstation.", USR, 0);

    F("ops_log.txt",
        "OPS LOG -- CIPHER BUREAU\n"
        "[09:14] Field operation NIGHTFALL -- status: active\n"
        "[09:31] Mole flag raised on internal comms audit\n"
        "[09:55] Director initiated investigation protocol\n");

    /* REVERSE puzzle
       Plaintext : "Director cipher protocol: shift 19"
       Reversed  : "91 tfihs :locotorp rehpic rotceriD" */
    FR("shift_table.enc",
        "91 tfihs :locotorp rehpic rotceriD");

    FU("field_agents.txt",
        "FIELD AGENTS -- REDACTED\n"
        "Agent CARDINAL : status ACTIVE [REDACTED]\n"
        "Agent WREN     : status ACTIVE [REDACTED]\n"
        "Agent FALCON   : status COMPROMISED -- leak\n"
        "[Full records require director clearance]\n");

    /* Node 2: records-vault (requires USER) */
    n = 2;
    add_node(l, "172.31.0.20", "records-vault",
             "Case records vault.", USR, 0);

    F("case_archive.txt",
        "MOLE INVESTIGATION -- CASE NOTES\n"
        "Internal audit flagged anomalous data transfers.\n"
        "Source traced to analyst access logs.\n"
        "Codename of mole held encrypted on director-pc.\n");

    F("clearance_map.txt",
        "NODE CLEARANCE REQUIREMENTS\n"
        "  cipher-gateway : GUEST\n"
        "  ops-terminal   : USER\n"
        "  records-vault  : USER\n"
        "  director-pc    : USER\n");

    FU("internal_report.txt",
        "INTERNAL SECURITY REPORT\n"
        "Mole codename confirmed and encrypted on director-pc.\n"
        "Cipher: director standard protocol (check ops-terminal).\n"
        "File: mole_file.enc -- apply correct shift to decode.\n");

    /* Node 3: director-pc (requires USER) */
    n = 3;
    add_node(l, "172.31.0.50", "director-pc",
             "Director's personal workstation.", USR, 0);

    F("director_readme.txt",
        "DIRECTOR'S WORKSTATION -- CLASSIFIED\n"
        "Classified files use bureau standard cipher.\n"
        "Cipher shift: see ops-terminal for protocol.\n"
        "Decrypt mole_file.enc to reveal the mole codename.\n");

    /* CAESAR-19 puzzle
       Plaintext : MOLE_EXPOSED_11
       Encoded   : FHEX_XQIHLXW_11 */
    FC("mole_file.enc", "FHEX_XQIHLXW_11", 19);

    FU("personnel_file.txt",
        "MOLE DOSSIER -- EYES ONLY\n"
        "The mole exploited analyst access over 6 months.\n"
        "Exposed 11 field identities before detection.\n"
        "Codename: MOLE_EXPOSED_11\n"
        "Status: apprehended -- case closed.\n");
}

/* Level 11 — Satellite Network (VERY HARD)
   First 5-node level. Three-part password assembled from: prefix on sat-hub,
   binary suffix on telemetry, and format confirmation from orion-core. Connecting
   to orion-core triggers a side-effect that unlocks override_code.txt, reinforcing
   the connect side-effect mechanic from level 6. A 200-second timer with a 40
   detection max demands both speed and precision. */
static void init_level11(void) {
    Level *l = &levels[11];
    memset(l, 0, sizeof(*l));
    l->id = 11;
    strncpy(l->name,     "Satellite Network",                 MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "VERY HARD",                       15);
    strncpy(l->objective,
        "Target: ORION satellite array (10.77.0.1).\n"
        "Hostile actor hijacking orbital positioning.\n"
        "Collect prefix from sat-hub, binary suffix from\n"
        "telemetry, then reach orion-core before time runs out.", 511);
    strncpy(l->warnings,
        "TIMED (200s) | 5 NODES | CONNECT SIDE-EFFECT", 255);
    strncpy(l->solution_password, "ORION_SAT_7721", 63);
    strncpy(l->user_password,     "sat_technician", 63);
    strncpy(l->hint,
        "HINT: Role is sat_technician (see operator_guide.txt).\n"
        "Get prefix ORION_SAT_ from sat-hub/partial_code.txt.\n"
        "Decode sat_dump.bin on telemetry node for suffix 7721.\n"
        "Connecting to orion-core auto-unlocks override_code.txt.", MAX_HINT - 1);
    l->max_attempts       = 4;
    l->detection_max      = 40;
    l->detection_per_fail = 20;
    l->has_timer          = 1;
    l->timer_seconds      = 200;
    l->available_cmds     = CMD_BASIC | CMD_HINT | CMD_LOGIN | CMD_LOGOUT
                          | CMD_DECRYPT | CMD_SAVE | CMD_INVENTORY
                          | CMD_SCAN    | CMD_CONNECT
                          | CMD_BRUTEFORCE | CMD_OVERRIDE
                          | CMD_SAVEGAME   | CMD_LOADGAME;

    /* Node 0: ground-ctrl (entry) */
    int n = 0;
    add_node(l, "10.77.0.1", "ground-ctrl",
             "ORION ground control -- entry.", PUB, 1);

    F("mission_log.txt",
        "ORION SATELLITE ARRAY -- MISSION LOG\n"
        "STATUS: CRITICAL -- hostile repositioning in progress\n"
        "Override window: 200 seconds before lock-out.\n"
        "All station access is logged by AI security system.\n");

    F("operator_guide.txt",
        "OPERATOR ACCESS\n"
        "Ground control access credential: sat_technician\n"
        "Full network topology available after authentication.\n");

    FU("network_topology.txt",
        "ORION NETWORK TOPOLOGY\n"
        "  10.77.0.1   ground-ctrl  (entry -- current)\n"
        "  10.77.0.10  comms-relay  (cipher standard)\n"
        "  10.77.0.20  sat-hub      (override prefix)\n"
        "  10.77.0.30  telemetry    (binary suffix)\n"
        "  10.77.0.99  orion-core   (authentication target)\n");

    /* Node 1: comms-relay (requires USER) */
    n = 1;
    add_node(l, "10.77.0.10", "comms-relay",
             "ORION communications relay.", USR, 0);

    F("relay_info.txt",
        "COMMS RELAY -- BANDWIDTH STATUS\n"
        "Uplink: 94.2 Mbps  |  Downlink: 87.1 Mbps\n"
        "Encryption: AES-256 + cipher layer on telemetry\n"
        "All telemetry files use the ORION cipher standard.\n");

    F("cipher_standard.txt",
        "ORION CIPHER STANDARD\n"
        "ORION cipher: Caesar shift 14 for all telemetry files.\n"
        "Apply this shift when decrypting any telemetry data.\n");

    FU("routing_table.txt",
        "ROUTING TABLE -- ORION NETWORK\n"
        "Route 1: ground-ctrl -> comms-relay -> sat-hub\n"
        "Route 2: ground-ctrl -> comms-relay -> telemetry\n"
        "Route 3: ground-ctrl -> comms-relay -> orion-core\n");

    /* Node 2: sat-hub (requires USER) */
    n = 2;
    add_node(l, "10.77.0.20", "sat-hub",
             "Satellite hub -- override coordination.", USR, 0);

    F("hub_status.txt",
        "SAT-HUB DIAGNOSTICS\n"
        "Orbital sync: ACTIVE\n"
        "Override relay: STANDBY -- awaiting authentication\n"
        "Repositioning cycle: T-minus 200 seconds\n");

    FU("partial_code.txt",
        "OVERRIDE PREFIX NOTE\n"
        "Override key prefix: ORION_SAT_\n"
        "Suffix is 4 digits from the telemetry node binary dump.\n"
        "Combine both components to form the full override key.\n");

    /* Node 3: telemetry (requires USER) */
    n = 3;
    add_node(l, "10.77.0.30", "telemetry",
             "Satellite telemetry node.", USR, 0);

    F("telemetry_readme.txt",
        "TELEMETRY NODE\n"
        "Orbital data is binary-encoded for transmission.\n"
        "Decode sat_dump.bin to retrieve the override suffix.\n"
        "The 4-digit result appends to the override prefix.\n");

    /* BINARY puzzle
       Encodes  : "7721"
       Binary   : 00110111 00110111 00110010 00110001 */
    FB("sat_dump.bin", "00110111 00110111 00110010 00110001");

    FU("orbital_log.txt",
        "ORBITAL REPOSITIONING LOG\n"
        "[T-00:00] Hostile command received\n"
        "[T-00:43] Repositioning cycle initiated\n"
        "[T-03:20] Override window closing -- act now\n");

    /* Node 4: orion-core (requires USER) */
    n = 4;
    add_node(l, "10.77.0.99", "orion-core",
             "ORION authentication core.", USR, 0);

    F("core_status.txt",
        "ORION CORE -- ACTIVE\n"
        "Authentication required to halt repositioning cycle.\n"
        "Connecting to this node activates override relay.\n"
        "Enter override key to abort hostile repositioning.\n");

    /* Locked -- auto-unlocked when connecting to orion-core */
    FL("override_code.txt",
        "OVERRIDE RELAY ACTIVE\n"
        "Override key format confirmed: ORION_SAT_[4 digits]\n"
        "Prefix : ORION_SAT_\n"
        "Suffix : 4-digit code from telemetry binary dump\n");

    FU("mission_critical.txt",
        "ORION CORE -- MISSION CRITICAL\n"
        "Full override key: ORION_SAT_ + binary suffix\n"
        "Binary suffix located on telemetry node (sat_dump.bin).\n"
        "Decode and combine to halt the repositioning cycle.\n");
}

/* Level 12 — Underground Market (EXTREME)
   Three fragments across three different puzzle types (binary, reverse, Caesar-23).
   Fragment 2 is behind a FLR (locked + reverse) file that only bruteforce can
   open. With 35 detection max and 12 per-fail, bruteforce (24 cost) consumes
   most of the budget, leaving 11 detection — one wrong login ends the run.
   No timer, but the 3-attempt cap creates equivalent tension. */
static void init_level12(void) {
    Level *l = &levels[12];
    memset(l, 0, sizeof(*l));
    l->id = 12;
    strncpy(l->name,     "Underground Market",                MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "EXTREME",                         15);
    strncpy(l->objective,
        "Target: SHADOWMARKET darknet marketplace (10.dark.0.1).\n"
        "Admin master key split into 3 fragments:\n"
        "  Frag 1: binary (shadow.bin) -- immediately available\n"
        "  Frag 2: reverse + LOCKED (bruteforce required)\n"
        "  Frag 3: Caesar-23 on admin-vault\n"
        "35 detection cap. ONE wrong login ends the run.", 511);
    strncpy(l->warnings,
        "EXTREME DETECTION | 3 ATTEMPTS | BRUTEFORCE REQUIRED", 255);
    strncpy(l->solution_password, "SHADOWMARKET_KEY", 63);
    strncpy(l->user_password,     "market_vendor",    63);
    strncpy(l->hint,
        "HINT: Decode shadow.bin first (binary = SHADOW).\n"
        "Login market_vendor, go to vendor-hub, bruteforce.\n"
        "locked_comms.enc (reverse) = MARKET_.\n"
        "On admin-vault: key.enc (Caesar-23) = KEY.\n"
        "Full password: SHADOWMARKET_KEY", MAX_HINT - 1);
    l->max_attempts       = 3;
    l->detection_max      = 35;
    l->detection_per_fail = 12;
    l->has_timer          = 0;
    l->available_cmds     = CMD_BASIC | CMD_HINT | CMD_LOGIN | CMD_LOGOUT
                          | CMD_DECRYPT | CMD_SAVE | CMD_INVENTORY
                          | CMD_SCAN    | CMD_CONNECT
                          | CMD_BRUTEFORCE | CMD_OVERRIDE
                          | CMD_SAVEGAME   | CMD_LOADGAME;

    /* Node 0: market-entry (entry) */
    int n = 0;
    add_node(l, "10.dark.0.1", "market-entry",
             "SHADOWMARKET -- anonymous entry node.", PUB, 1);

    F("welcome.onion",
        "SHADOWMARKET -- PRIVATE NETWORK\n"
        "Market vendor credentials: market_vendor\n"
        "Warning: 3 failed logins = PERMANENT BAN\n"
        "Stay anonymous. Stay ghost.\n");

    F("rules.txt",
        "MARKET RULES\n"
        "1. Vendor credentials must not be shared.\n"
        "2. All transactions are encrypted end-to-end.\n"
        "3. Three authentication failures = permanent ban.\n"
        "4. Admin master key is split across three nodes.\n");

    /* BINARY puzzle
       Encodes  : "SHADOW"
       Binary   : 01010011 01001000 01000001 01000100 01001111 01010111 */
    FB("shadow.bin",
        "01010011 01001000 01000001 01000100 01001111 01010111");

    FU("vendor_info.txt",
        "VENDOR SUBSYSTEM MAP\n"
        "  10.dark.0.10  vendor-hub   (vendor listings)\n"
        "  10.dark.0.20  escrow-srv   (transaction escrow)\n"
        "  10.dark.0.50  admin-vault  (admin partition)\n"
        "Admin key fragment locations: vendor-hub, admin-vault.\n");

    /* Node 1: vendor-hub (requires USER) */
    n = 1;
    add_node(l, "10.dark.0.10", "vendor-hub",
             "Vendor listings and communications hub.", USR, 0);

    F("listings.txt",
        "VENDOR LISTINGS -- ACTIVE\n"
        "Vendor 0x1A : electronics  [VERIFIED]\n"
        "Vendor 0x2B : documents    [VERIFIED]\n"
        "Vendor 0x3C : credentials  [SUSPENDED]\n"
        "Admin comms archive: locked -- requires bypass.\n");

    /* REVERSE puzzle + LOCKED (bruteforce required)
       Plaintext : "MARKET_"
       Reversed  : "_TEKRAM" */
    FLR("locked_comms.enc", "_TEKRAM");

    FU("cipher_note.txt",
        "ADMIN VAULT CIPHER\n"
        "Admin vault files use Caesar shift 23.\n"
        "Apply shift 23 when decrypting vault .enc files.\n");

    /* Node 2: escrow-srv (requires USER) */
    n = 2;
    add_node(l, "10.dark.0.20", "escrow-srv",
             "Transaction escrow server.", USR, 0);

    F("escrow_log.txt",
        "ESCROW TRANSACTION LOG\n"
        "[TX-0091] 0x1A -> 0x4F : 2.4 BTC -- HELD\n"
        "[TX-0092] 0x2B -> 0x7E : 0.8 BTC -- RELEASED\n"
        "[TX-0093] 0x3C -> 0x9A : 5.0 BTC -- FROZEN\n");

    FU("admin_note.txt",
        "ADMIN KEY ASSEMBLY NOTE\n"
        "Master key is split across three nodes:\n"
        "  Fragment 1: binary decode on market-entry\n"
        "  Fragment 2: reverse decode on vendor-hub (locked)\n"
        "  Fragment 3: Caesar-23 decode on admin-vault\n"
        "Combine all three fragments in order.\n");

    /* Node 3: admin-vault (requires USER) */
    n = 3;
    add_node(l, "10.dark.0.50", "admin-vault",
             "Admin control vault -- restricted.", USR, 0);

    F("vault_notice.txt",
        "ADMIN VAULT -- RESTRICTED ZONE\n"
        "Cipher: Caesar shift 23 (see vendor-hub cipher_note).\n"
        "Decrypt key.enc to retrieve the final key fragment.\n");

    /* CAESAR-23 puzzle
       Plaintext : KEY
       Encoded   : HBV */
    FC("key.enc", "HBV", 23);

    FU("master_readme.txt",
        "MASTER KEY ASSEMBLY\n"
        "Fragment 1 (binary)   : SHADOW\n"
        "Fragment 2 (reverse)  : MARKET_\n"
        "Fragment 3 (Caesar-23): KEY\n"
        "Combined              : SHADOWMARKET_KEY\n"
        "This is the admin master key for SHADOWMARKET.\n");
}

/* Level 13 — Quantum Research Lab (EXTREME)
   First level requiring both bruteforce AND override. Detection per-fail is
   tuned to 8 so both mandatory actions (bruteforce = 16, override = 24) total
   40 of the 50 max — survivable, but a single wrong login after them brings
   the total to 48, and a second is fatal. Five nodes with a 200-second timer.
   The locked_manifest.txt read after bruteforce acts as an in-world breadcrumb
   directing the player to the override step. */
static void init_level13(void) {
    Level *l = &levels[13];
    memset(l, 0, sizeof(*l));
    l->id = 13;
    strncpy(l->name,     "Quantum Research Lab",              MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "EXTREME",                         15);
    strncpy(l->objective,
        "Target: NovaTech Quantum facility (10.nova.0.1).\n"
        "Classified experiment BREACH is at stake.\n"
        "Two fragments across 5 nodes. BOTH bruteforce\n"
        "AND override are required -- consume budget wisely.", 511);
    strncpy(l->warnings,
        "TIMED (200s) | BRUTEFORCE + OVERRIDE BOTH REQUIRED", 255);
    strncpy(l->solution_password, "QUANTUM_BREACH_9", 63);
    strncpy(l->user_password,     "lab_access_7",     63);
    strncpy(l->hint,
        "HINT: Credential is lab_access_7 (staff_access.txt).\n"
        "Decode quantum.bin on lab-terminal (binary = QUANTUM_).\n"
        "Bruteforce on quantum-relay unlocks locked_manifest.txt.\n"
        "Override on quantum-core unlocks .classified_key.", MAX_HINT - 1);
    l->max_attempts       = 3;
    l->detection_max      = 50;
    l->detection_per_fail = 8;
    l->has_timer          = 1;
    l->timer_seconds      = 200;
    l->available_cmds     = CMD_BASIC | CMD_HINT | CMD_LOGIN | CMD_LOGOUT
                          | CMD_DECRYPT | CMD_SAVE | CMD_INVENTORY
                          | CMD_SCAN    | CMD_CONNECT
                          | CMD_BRUTEFORCE | CMD_OVERRIDE
                          | CMD_SAVEGAME   | CMD_LOADGAME;

    /* Node 0: research-hq (entry) */
    int n = 0;
    add_node(l, "10.nova.0.1", "research-hq",
             "NovaTech Quantum -- research headquarters.", PUB, 1);

    F("facility_welcome.txt",
        "NOVATECH QUANTUM RESEARCH FACILITY\n"
        "AI security monitoring all sessions.\n"
        "Override window: 200 seconds before lockdown.\n"
        "Breach of classified experiment BREACH is critical.\n");

    F("staff_access.txt",
        "LAB ACCESS CREDENTIALS\n"
        "Lab access credentials: lab_access_7\n"
        "Full network layout available after authentication.\n");

    FU("security_brief.txt",
        "SECURITY BRIEF -- AI MONITORING\n"
        "All nodes are under AI surveillance.\n"
        "  10.nova.0.10  lab-terminal  (fragment 1)\n"
        "  10.nova.0.20  data-core     (cipher spec)\n"
        "  10.nova.0.30  quantum-relay (bruteforce target)\n"
        "  10.nova.0.99  quantum-core  (override target)\n");

    /* Node 1: lab-terminal (requires USER) */
    n = 1;
    add_node(l, "10.nova.0.10", "lab-terminal",
             "Lab terminal -- experiment logs.", USR, 0);

    F("lab_readme.txt",
        "LAB TERMINAL\n"
        "Experiment data is binary-encoded for security.\n"
        "Decode quantum.bin to retrieve password fragment 1.\n");

    /* BINARY puzzle
       Encodes  : "QUANTUM_"
       Binary   : 01010001 01010101 01000001 01001110
                  01010100 01010101 01001101 01011111 */
    FB("quantum.bin",
        "01010001 01010101 01000001 01001110 01010100 01010101 01001101 01011111");

    FU("experiment_log.txt",
        "EXPERIMENT BREACH -- TIMELINE\n"
        "[Day 1]  Quantum coherence baseline established\n"
        "[Day 14] Anomalous entanglement pattern detected\n"
        "[Day 31] AI security protocol initiated -- BREACH\n"
        "Classification: TOP SECRET -- need-to-know only\n");

    /* Node 2: data-core (requires USER) */
    n = 2;
    add_node(l, "10.nova.0.20", "data-core",
             "Research data core.", USR, 0);

    F("data_index.txt",
        "DATA CORE -- FILE MANIFEST\n"
        "cipher_spec.txt    : quantum cipher specification\n"
        "access_partial.txt : partial override information\n");

    F("cipher_spec.txt",
        "QUANTUM CORE CIPHER\n"
        "Quantum core cipher: Caesar shift 23.\n"
        "Apply shift 23 when decrypting quantum-core files.\n");

    FU("access_partial.txt",
        "PARTIAL ACCESS NOTE\n"
        "BREACH experiment suffix is digit 9.\n"
        "Core cipher encodes the full string BREACH_9.\n"
        "Decrypt breach.enc on quantum-core with shift 23.\n");

    /* Node 3: quantum-relay (requires USER) */
    n = 3;
    add_node(l, "10.nova.0.30", "quantum-relay",
             "Quantum network relay.", USR, 0);

    F("relay_diagnostics.txt",
        "QUANTUM RELAY -- DIAGNOSTICS\n"
        "Quantum channel: ACTIVE\n"
        "Entanglement fidelity: 97.3%\n"
        "Security partition: LOCKED -- bypass required\n");

    /* Locked until bruteforce */
    FL("locked_manifest.txt",
        "QUANTUM-CORE OVERRIDE PATHWAY\n"
        "Authentication bypass achieved on quantum-relay.\n"
        "quantum-core override pathway confirmed active.\n"
        "Use 'override' command on quantum-core to unlock\n"
        "the classified partition (.classified_key).\n");

    /* Node 4: quantum-core (requires USER) */
    n = 4;
    add_node(l, "10.nova.0.99", "quantum-core",
             "Quantum authentication core -- classified.", USR, 0);

    F("core_status.txt",
        "QUANTUM CORE -- ACTIVE\n"
        "Override required to access classified partition.\n"
        "Run 'override' to unlock .classified_key.\n");

    /* CAESAR-23 puzzle
       Plaintext : BREACH_9
       Encoded   : YOBXZE_9 */
    FC("breach.enc", "YOBXZE_9", 23);

    /* Hidden + locked -- unlocked by override */
    add_file(l, n, ".classified_key",
        "CLASSIFIED PARTITION UNLOCKED\n"
        "Override sequence accepted.\n"
        "Fragment 2: BREACH_9\n"
        "Full password: QUANTUM_BREACH_9\n",
        USR, 1, 0, PUZZLE_NONE, 0, 1);
}

/* Level 14 — GHOST Protocol (LEGENDARY)
   The final level. Six nodes, four fragments, three puzzle types, bruteforce
   and override both required. Bruteforce (30) + override (45) = 75 of 80
   detection consumed by mandatory actions. One wrong login (15) = 90 — game
   over. The 120-second timer is the shortest in the game, requiring the player
   to have a planned route before they start. fragment-delta has a connect
   side-effect that unlocks blackout_info.txt, providing the Caesar shift and
   the final override direction in a single connection step. */
static void init_level14(void) {
    Level *l = &levels[14];
    memset(l, 0, sizeof(*l));
    l->id = 14;
    strncpy(l->name,     "GHOST Protocol",                    MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "LEGENDARY",                       15);
    strncpy(l->objective,
        "ZERO DAY. Logic bomb in global financial clearing.\n"
        "Triggers in 2 minutes. Deactivation key split across\n"
        "5 nodes: 4 fragments, 3 puzzle types, bruteforce,\n"
        "override. Every action counts. No margin for error.", 511);
    strncpy(l->warnings,
        "TIMED (120s) | ALL COMMANDS | LEGENDARY DIFFICULTY", 255);
    strncpy(l->solution_password, "ZERO_DAY_BLACKOUT", 63);
    strncpy(l->user_password,     "ghost_zero",         63);
    strncpy(l->hint,
        "HINT: Credential is ghost_zero (zero_day.txt).\n"
        "Frag1: zero.bin (binary)=ZERO_  Frag2: day.enc (reverse,bruteforce)=DAY_\n"
        "Get shift 21 from fragment-delta (blackout_info auto-unlocks).\n"
        "Frag3: black.enc (Caesar-21)=BLACK  Frag4: override on omega-core.\n"
        "Full key: ZERO_DAY_BLACKOUT", MAX_HINT - 1);
    l->max_attempts       = 3;
    l->detection_max      = 80;
    l->detection_per_fail = 15;
    l->has_timer          = 1;
    l->timer_seconds      = 120;
    l->available_cmds     = CMD_BASIC | CMD_HINT | CMD_LOGIN | CMD_LOGOUT
                          | CMD_DECRYPT | CMD_SAVE | CMD_INVENTORY
                          | CMD_SCAN    | CMD_CONNECT
                          | CMD_BRUTEFORCE | CMD_OVERRIDE
                          | CMD_SAVEGAME   | CMD_LOADGAME;

    /* Node 0: day-zero-entry (entry) */
    int n = 0;
    add_node(l, "0.zero.0.1", "day-zero-entry",
             "ZERO DAY -- anonymous command entry.", PUB, 1);

    F("zero_day.txt",
        "ZERO DAY ALERT -- LOGIC BOMB ACTIVE\n"
        "Target: global financial clearing infrastructure.\n"
        "Detonation: 120 seconds from session start.\n"
        "Anonymous credential: ghost_zero\n"
        "Four fragments. Collect all. Combine. Deactivate.\n");

    FU("status_brief.txt",
        "ZERO DAY NETWORK -- NODE MAP\n"
        "  0.zero.0.10  fragment-alpha  (binary fragment)\n"
        "  0.zero.0.20  fragment-beta   (reverse fragment -- locked)\n"
        "  0.zero.0.30  fragment-gamma  (Caesar fragment)\n"
        "  0.zero.0.40  fragment-delta  (cipher key node)\n"
        "  0.zero.0.99  omega-core      (override target)\n");

    FU("assembly_guide.txt",
        "DEACTIVATION KEY ASSEMBLY\n"
        "Four fragments. Collect in any order. Combine.\n"
        "Fragment 1: binary decode on fragment-alpha\n"
        "Fragment 2: reverse decode on fragment-beta (locked)\n"
        "Fragment 3: Caesar decode on fragment-gamma\n"
        "Fragment 4: override required on omega-core\n");

    /* Node 1: fragment-alpha (requires USER) */
    n = 1;
    add_node(l, "0.zero.0.10", "fragment-alpha",
             "Fragment alpha node.", USR, 0);

    F("alpha_readme.txt",
        "FRAGMENT ALPHA NODE\n"
        "Fragment 1 is binary-encoded in zero.bin.\n"
        "Decode it to retrieve the first key component.\n");

    /* BINARY puzzle
       Encodes  : "ZERO_"
       Binary   : 01011010 01000101 01010010 01001111 01011111 */
    FB("zero.bin",
        "01011010 01000101 01010010 01001111 01011111");

    /* Node 2: fragment-beta (requires USER) */
    n = 2;
    add_node(l, "0.zero.0.20", "fragment-beta",
             "Fragment beta node.", USR, 0);

    F("beta_readme.txt",
        "FRAGMENT BETA NODE\n"
        "Fragment 2 is reverse-encoded but access is locked.\n"
        "Authentication bypass required to reach it.\n");

    /* REVERSE puzzle + LOCKED (bruteforce required)
       Plaintext : "DAY_"
       Reversed  : "_YAD" */
    FLR("day.enc", "_YAD");

    F("bruteforce_notice.txt",
        "AUTHENTICATION BYPASS NOTICE\n"
        "Fragment 2 archive is protected by authentication.\n"
        "Standard bypass (bruteforce) required to access it.\n");

    /* Node 3: fragment-gamma (requires USER) */
    n = 3;
    add_node(l, "0.zero.0.30", "fragment-gamma",
             "Fragment gamma node.", USR, 0);

    F("gamma_readme.txt",
        "FRAGMENT GAMMA NODE\n"
        "Fragment 3 is Caesar-encoded in black.enc.\n"
        "Cipher shift is documented on fragment-delta.\n");

    /* CAESAR-21 puzzle
       Plaintext : BLACK
       Encoded   : WGVXF */
    FC("black.enc", "WGVXF", 21);

    /* Node 4: fragment-delta (requires USER) */
    n = 4;
    add_node(l, "0.zero.0.40", "fragment-delta",
             "Fragment delta node -- cipher key.", USR, 0);

    F("delta_ops.txt",
        "BLACKOUT PROTOCOL CIPHER\n"
        "Fragment 3 cipher: Caesar shift 21.\n"
        "Apply to black.enc on fragment-gamma.\n"
        "Fragment 4 is on omega-core behind neural override.\n");

    /* Auto-unlocked when connecting to fragment-delta */
    FL("blackout_info.txt",
        "BLACKOUT PROTOCOL -- INTEL\n"
        "Fragment 3 cipher confirmed: Caesar shift 21.\n"
        "Fragment 4: located on omega-core node.\n"
        "Access method: neural override command required.\n");

    /* Node 5: omega-core (requires USER) */
    n = 5;
    add_node(l, "0.zero.0.99", "omega-core",
             "OMEGA CORE -- final deactivation node.", USR, 0);

    F("omega_status.txt",
        "OMEGA CORE -- NEURAL OVERRIDE REQUIRED\n"
        "Classified partition locked behind neural security.\n"
        "Use 'override' to unlock .deactivation_key.\n"
        "This is the final step. No margin for error.\n");

    F("core_log.txt",
        "[T-120s] Logic bomb armed -- countdown active\n"
        "[T-090s] External breach detected\n"
        "[T-060s] Override window: OPEN\n"
        "[T-000s] Deactivation or detonation -- your choice\n");

    /* Hidden + locked -- unlocked by override */
    FHL(".deactivation_key",
        "DEACTIVATION KEY UNLOCKED\n"
        "Fragment 4: OUT\n"
        "Full deactivation key: ZERO_DAY_BLACKOUT\n"
        "Enter this as the login password to deactivate.\n");
}

/* ====================================================================
 * Levels 16–25: MYTHIC through TRANSCENDENT tiers.
 * These levels introduce four new cipher families (XOR, Vigenère, hex,
 * base64), routing-order requirements, honeypot decoy nodes, log-grep
 * forensics, multi-fragment key assembly via 'combine', and on the
 * final stage adaptive detection that punishes repeated commands.
 * ==================================================================== */

/* Level 16 (idx 15) — Crypto Exchange Heist (MYTHIC)
   Drain a cold wallet from ZenithCoin. Four nodes, three new cipher types
   stacked across separate fragments. Player joins fragments via inventory
   and 'combine' to assemble ZEN1TH_C0LD_V@ULT. */
static void init_level15(void) {
    Level *l = &levels[15];
    memset(l, 0, sizeof(*l));
    l->id = 15;
    strncpy(l->name,     "Crypto Exchange Heist", MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "MYTHIC",              15);
    strncpy(l->objective,
        "ZenithCoin's cold-wallet vault is reachable through\n"
        "their HSM bridge. Three fragments of the vault key\n"
        "are scattered across trading-engine, hsm-bridge, and\n"
        "cold-vault. Combine them to assemble the master key.\n"
        "New ciphers: hex bytes, XOR, base64. Use 'combine'.", 511);
    strncpy(l->warnings,
        "Exchange runs intrusion analytics — keep moves tight.", 255);
    strncpy(l->solution_password, "ZEN1TH_C0LD_V@ULT", 63);
    strncpy(l->user_password,     "trader_oa",         63);
    strncpy(l->hint,
        "HINT: User cred is trader_oa.\n"
        "Frag1 hex on trading-engine -> ZEN1TH_\n"
        "Frag2 XOR(key=ZENITH) on hsm-bridge -> C0LD_\n"
        "Frag3 Caesar-13 on cold-vault -> V@ULT\n"
        "save each fragment, then 'combine' for the full key.", MAX_HINT - 1);
    l->max_attempts       = 4;
    l->detection_max      = 80;
    l->detection_per_fail = 20;
    l->has_timer          = 1;
    l->timer_seconds      = 240;
    l->available_cmds     = CMD_BASIC | CMD_HINT | CMD_LOGIN | CMD_LOGOUT
                          | CMD_DECRYPT | CMD_SAVE | CMD_INVENTORY
                          | CMD_SCAN    | CMD_CONNECT | CMD_COMBINE | CMD_DROP
                          | CMD_SAVEGAME | CMD_LOADGAME;

    int n = 0;
    add_node(l, "203.0.113.10", "gateway",
             "ZenithCoin public API gateway.", PUB, 1);
    F("welcome.txt",
        "ZenithCoin Exchange — Public Gateway\n"
        "Authorised personnel only. Trading API on this segment.\n");
    F("staff_memo.txt",
        "Memo to ops: trader_oa is the read-only account on the\n"
        "trading engine. Use it for monitoring, not for execution.\n");
    F("network_map.txt",
        "Internal segment map:\n"
        "  10.10.10.20  trading-engine  (USER)\n"
        "  10.10.10.30  hsm-bridge      (USER)\n"
        "  10.10.10.40  cold-vault      (USER)\n");

    n = 1;
    add_node(l, "10.10.10.20", "trading-engine",
             "Order matching engine.", USR, 0);
    F("README.txt",
        "TRADING ENGINE — fragment 1 of vault key stored in frag1.hex.\n"
        "Format: hex bytes (space-separated) -> ASCII.\n");
    FX("frag1.hex", "5A 45 4E 31 54 48 5F");

    n = 2;
    add_node(l, "10.10.10.30", "hsm-bridge",
             "HSM XOR-key relay.", USR, 0);
    F("README.txt",
        "HSM BRIDGE — fragment 2 in frag2.xor.\n"
        "Cipher: XOR with the bridge identity key (the exchange name).\n");
    FXOR("frag2.xor", "19 75 02 0D 0B", "ZENITH");

    n = 3;
    add_node(l, "10.10.10.40", "cold-vault",
             "Cold storage authoriser.", USR, 0);
    F("README.txt",
        "COLD VAULT — fragment 3 in frag3.enc.\n"
        "Legacy operator note: \"shift 13 — half the alphabet.\"\n");
    FC("frag3.enc", "I@HYG", 13);
    F("assembly_hint.txt",
        "Concatenate fragment 1 + 2 + 3 in order. Use:\n"
        "  combine 1 2 3   (with each fragment saved to inventory)\n");
}

/* Level 17 (idx 16) — Industrial SCADA Sabotage (MYTHIC)
   Pump-station control net. Vigenère + reverse, plus a routing constraint
   on plc-core: must traverse historian first to receive valid PLC tags. */
static void init_level16(void) {
    Level *l = &levels[16];
    memset(l, 0, sizeof(*l));
    l->id = 16;
    strncpy(l->name,     "Industrial SCADA Sabotage", MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "MYTHIC",                  15);
    strncpy(l->objective,
        "Pump-station control net for a city water grid.\n"
        "Two fragments: a Vigenère-encoded set-point block on\n"
        "rtu-1, and a reverse-encoded override token on rtu-2.\n"
        "PLC core enforces routing -- visit historian first.", 511);
    strncpy(l->warnings,
        "Bad routing fries the PLC. Mind your hops.", 255);
    strncpy(l->solution_password, "SET_P01NT_OVERRIDE", 63);
    strncpy(l->user_password,     "plc_op_3",           63);
    strncpy(l->hint,
        "HINT: User cred is plc_op_3 (visible on scada-master).\n"
        "Frag1 Vigenère(key=HYDRA) on rtu-1 -> SET_P01NT_\n"
        "Frag2 reverse on rtu-2 -> OVERRIDE\n"
        "plc-core requires prior visit to historian.\n"
        "combine 1 2 -> SET_P01NT_OVERRIDE", MAX_HINT - 1);
    l->max_attempts       = 4;
    l->detection_max      = 70;
    l->detection_per_fail = 25;
    l->has_timer          = 1;
    l->timer_seconds      = 240;
    l->available_cmds     = CMD_BASIC | CMD_HINT | CMD_LOGIN | CMD_LOGOUT
                          | CMD_DECRYPT | CMD_SAVE | CMD_INVENTORY
                          | CMD_SCAN    | CMD_CONNECT | CMD_COMBINE | CMD_DROP
                          | CMD_SAVEGAME | CMD_LOADGAME;

    int n = 0;
    add_node(l, "172.16.0.10", "scada-master",
             "Operator HMI — control room.", PUB, 1);
    F("login_banner.txt",
        "SCADA HMI v4.1 — operator credential: plc_op_3\n"
        "All commands logged. Tampering is a federal offence.\n");
    F("topology.txt",
        "Control segment:\n"
        "  172.16.0.20 rtu-1       (USER)\n"
        "  172.16.0.21 rtu-2       (USER)\n"
        "  172.16.0.30 historian   (USER)\n"
        "  172.16.0.99 plc-core    (USER, routed via historian)\n");

    n = 1;
    add_node(l, "172.16.0.20", "rtu-1", "Remote terminal unit 1.", USR, 0);
    F("README.txt",
        "RTU-1 — fragment 1 in setpoint.vig.\n"
        "Field-team key sticker: \"HYDRA pump set\".\n");
    FVIG("setpoint.vig", "ZCW_G01NA_", "HYDRA");

    n = 2;
    add_node(l, "172.16.0.21", "rtu-2", "Remote terminal unit 2.", USR, 0);
    F("README.txt",
        "RTU-2 — fragment 2 in token.rev (reverse text).\n");
    FR("token.rev", "EDIRREVO");

    n = 3;
    add_node(l, "172.16.0.30", "historian", "Plant historian DB.", USR, 0);
    F("plc_tags.txt",
        "PLC TAG VALIDATION REGISTRY\n"
        "Connection to plc-core requires prior historian session.\n"
        "Routing tag emitted on access. Do not skip.\n");

    n = 4;
    add_node(l, "172.16.0.99", "plc-core",
             "PLC programmable logic controller.", USR, 0);
    route_after(l, "historian");
    F("core_status.txt",
        "PLC CORE — set-point write authority.\n"
        "Submit the assembled SET_P01NT_OVERRIDE key.\n");
    F("assembly_hint.txt",
        "Two fragments. combine 1 2 in inventory order.\n");
}

/* Level 18 (idx 17) — Telecom Backbone (MYTHIC++)
   Tier-1 ISP core. Three fragments: base64, hex, XOR. Transit-core requires
   prior bgp-reflector visit to enforce realistic AS-path traversal. */
static void init_level17(void) {
    Level *l = &levels[17];
    memset(l, 0, sizeof(*l));
    l->id = 17;
    strncpy(l->name,     "Telecom Backbone Hijack", MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "MYTHIC++",              15);
    strncpy(l->objective,
        "Hijack a tier-1 backbone via the BGP route reflector.\n"
        "Three encoded fragments across the transit fabric --\n"
        "base64, raw hex, XOR. Transit-core only accepts the\n"
        "session if you came in through bgp-reflector first.", 511);
    strncpy(l->warnings, "TIMED 200s | BRUTEFORCE may be needed", 255);
    strncpy(l->solution_password, "BGP_HIJACK_PRIME", 63);
    strncpy(l->user_password,     "net_eng_99",       63);
    strncpy(l->hint,
        "HINT: User cred net_eng_99 (edge-router peering banner).\n"
        "Frag1 base64 on bgp-reflector -> BGP_\n"
        "Frag2 hex on transit-core -> HIJACK_\n"
        "Frag3 XOR(key=AS1337) on peering-x -> PRIME\n"
        "Routing: edge-router -> bgp-reflector -> transit-core.\n"
        "combine 1 2 3 -> BGP_HIJACK_PRIME", MAX_HINT - 1);
    l->max_attempts       = 4;
    l->detection_max      = 70;
    l->detection_per_fail = 20;
    l->has_timer          = 1;
    l->timer_seconds      = 200;
    l->available_cmds     = CMD_BASIC | CMD_HINT | CMD_LOGIN | CMD_LOGOUT
                          | CMD_DECRYPT | CMD_SAVE | CMD_INVENTORY
                          | CMD_SCAN    | CMD_CONNECT | CMD_COMBINE | CMD_DROP
                          | CMD_BRUTEFORCE
                          | CMD_SAVEGAME | CMD_LOADGAME;

    int n = 0;
    add_node(l, "10.20.0.1", "edge-router",
             "Customer-edge router.", PUB, 1);
    F("peering_banner.txt",
        "Tier-1 backbone — restricted. Engineering creds: net_eng_99\n"
        "AS path validation enforced on transit core.\n");
    F("network_map.txt",
        "  10.20.0.10  bgp-reflector  (USER)\n"
        "  10.20.0.20  transit-core   (USER, routed via bgp-reflector)\n"
        "  10.20.0.30  peering-x      (USER)\n"
        "  10.20.0.40  route-optimizer(USER)\n");

    n = 1;
    add_node(l, "10.20.0.10", "bgp-reflector",
             "BGP route reflector.", USR, 0);
    F("README.txt",
        "BGP-RR — fragment 1 in frag1.b64 (base64).\n");
    FB64("frag1.b64", "QkdQXw==");

    n = 2;
    add_node(l, "10.20.0.20", "transit-core",
             "Transit core router.", USR, 0);
    route_after(l, "bgp-reflector");
    F("README.txt",
        "TRANSIT — fragment 2 in frag2.hex (raw hex bytes).\n");
    FX("frag2.hex", "48 49 4A 41 43 4B 5F");

    n = 3;
    add_node(l, "10.20.0.30", "peering-x",
             "Peering exchange interface.", USR, 0);
    F("README.txt",
        "PEERING-X — fragment 3 in frag3.xor.\n"
        "Cipher key is our peering AS identifier (AS#### with code).\n");
    FXOR("frag3.xor", "11 01 78 7E 76", "AS1337");

    n = 4;
    add_node(l, "10.20.0.40", "route-optimizer",
             "Route optimisation appliance.", USR, 0);
    F("README.txt",
        "OPTIMIZER -- diagnostics only. No fragments here.\n"
        "Use bruteforce on this node only if peering-x rejects you.\n");
}

/* Level 19 (idx 18) — Spy Satellite Imagery Vault (APEX)
   Three encoded fragments: Vigenère, hex, reverse. */
static void init_level18(void) {
    Level *l = &levels[18];
    memset(l, 0, sizeof(*l));
    l->id = 18;
    strncpy(l->name,     "Spy Satellite Imagery Vault", MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "APEX",                      15);
    strncpy(l->objective,
        "Recover the KEYHOLE recon archive. Ground-station\n"
        "issues USER creds; the key splits across uplink-relay\n"
        "(Vigenère), decryption-rig (hex), and one of two image\n"
        "vaults (reverse). One vault is stale -- pick the live one.", 511);
    strncpy(l->warnings, "Detection ceiling is brutal here.", 255);
    strncpy(l->solution_password, "KEYHOLE_RECON_X9", 63);
    strncpy(l->user_password,     "ground_op_7",      63);
    strncpy(l->hint,
        "HINT: User cred ground_op_7 (groundstation banner).\n"
        "Frag1 Vigenère(key=ORBIT) on uplink-relay -> KEYHOLE_\n"
        "Frag2 hex on decryption-rig -> RECON_\n"
        "Frag3 reverse on vault-A    -> X9\n"
        "(vault-B is decoy). combine 1 2 3 -> KEYHOLE_RECON_X9", MAX_HINT - 1);
    l->max_attempts       = 3;
    l->detection_max      = 60;
    l->detection_per_fail = 30;
    l->has_timer          = 1;
    l->timer_seconds      = 200;
    l->available_cmds     = CMD_BASIC | CMD_HINT | CMD_LOGIN | CMD_LOGOUT
                          | CMD_DECRYPT | CMD_SAVE | CMD_INVENTORY
                          | CMD_SCAN    | CMD_CONNECT | CMD_COMBINE | CMD_DROP
                          | CMD_SAVEGAME | CMD_LOADGAME;

    int n = 0;
    add_node(l, "198.51.100.1", "ground-station",
             "Satellite ground station.", PUB, 1);
    F("welcome.txt",
        "KEYHOLE GROUND OPS — ops cred: ground_op_7\n"
        "Vault is divided into two compartments. Only one is live.\n"
        "Cross-check vault status before pulling fragments.\n");
    F("topology.txt",
        "  10.50.0.10 uplink-relay    (USER)\n"
        "  10.50.0.20 decryption-rig  (USER)\n"
        "  10.50.0.30 vault-A         (USER)\n"
        "  10.50.0.40 vault-B         (USER, decoy)\n");

    n = 1;
    add_node(l, "10.50.0.10", "uplink-relay",
             "Satellite uplink relay.", USR, 0);
    F("README.txt",
        "RELAY — fragment 1 in keyhole.vig.\n"
        "Cipher key is our orbital track designator.\n");
    FVIG("keyhole.vig", "YVZPHZV_", "ORBIT");

    n = 2;
    add_node(l, "10.50.0.20", "decryption-rig",
             "Decryption rig.", USR, 0);
    F("README.txt", "RIG — fragment 2 in recon.hex.\n");
    FX("recon.hex", "52 45 43 4F 4E 5F");

    n = 3;
    add_node(l, "10.50.0.30", "vault-A", "Vault A — live.", USR, 0);
    F("README.txt", "VAULT A — live. Fragment 3 in tail.rev.\n");
    FR("tail.rev", "9X");

    n = 4;
    add_node(l, "10.50.0.40", "vault-B", "Vault B — stale.", USR, 0);
    F("README.txt",
        "VAULT B — last sync 47 days ago. Frags here are stale.\n"
        "Stale fragment: 7Q (will not assemble).\n");
    FR("tail.rev", "Q7");
}

/* Level 20 (idx 19) — Forensic Counter-Hack (APEX)
   Someone is hacking back. Use grep on a busy auth log to find the
   attacker's window — the seconds digit of the timestamp is the Caesar
   shift for the next fragment. */
static void init_level19(void) {
    Level *l = &levels[19];
    memset(l, 0, sizeof(*l));
    l->id = 19;
    strncpy(l->name,     "Forensic Counter-Hack", MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "APEX",                15);
    strncpy(l->objective,
        "Hostile is exfiltrating from your honeypot. Trace them\n"
        "via auth logs (grep), derive the cipher shift from the\n"
        "intrusion timestamp, decode the response packet, then\n"
        "burn their C2. New tool: grep <pattern> <file>.", 511);
    strncpy(l->warnings, "TIMED 300s. Hostile is active.", 255);
    strncpy(l->solution_password, "BURN_THE_C2_NOW", 63);
    strncpy(l->user_password,     "ir_analyst",      63);
    strncpy(l->hint,
        "HINT: User cred ir_analyst.\n"
        "grep KEY_MISMATCH on /var/log/auth on relay-honey.\n"
        "Match line shows '...:09]' -- shift = 9.\n"
        "Frag1 Caesar-9 on attacker-relay -> BURN_THE_\n"
        "Frag2 hex on attacker-c2          -> C2_NOW\n"
        "combine 1 2 -> BURN_THE_C2_NOW", MAX_HINT - 1);
    l->max_attempts       = 4;
    l->detection_max      = 70;
    l->detection_per_fail = 20;
    l->has_timer          = 1;
    l->timer_seconds      = 300;
    l->available_cmds     = CMD_BASIC | CMD_HINT | CMD_LOGIN | CMD_LOGOUT
                          | CMD_DECRYPT | CMD_SAVE | CMD_INVENTORY
                          | CMD_SCAN    | CMD_CONNECT | CMD_COMBINE | CMD_DROP
                          | CMD_GREP
                          | CMD_SAVEGAME | CMD_LOADGAME;

    int n = 0;
    add_node(l, "10.0.0.66", "ir-bastion",
             "Incident-response jump box.", PUB, 1);
    F("welcome.txt",
        "IR Bastion — analyst credential: ir_analyst\n"
        "Hostile traffic visible on relay-honey logs. Use grep.\n");
    F("topology.txt",
        "  10.0.0.67 relay-honey      (USER, log-heavy)\n"
        "  10.0.0.68 attacker-relay   (USER)\n"
        "  10.0.0.69 attacker-c2      (USER)\n"
        "  10.0.0.70 identity-leak    (USER)\n");

    n = 1;
    add_node(l, "10.0.0.67", "relay-honey",
             "Honeypot relay (logs).", USR, 0);
    F("notes.txt",
        "Filter the busy auth log to find the AUTH_FAIL line\n"
        "with reason=KEY_MISMATCH. The seconds field of that\n"
        "timestamp is the Caesar shift for fragment 1.\n");
    F("auth.log",
        "[2026-04-15 03:11:22] AUTH_OK   src=10.0.0.4   user=cron\n"
        "[2026-04-15 03:12:01] AUTH_OK   src=10.0.0.4   user=cron\n"
        "[2026-04-15 03:13:55] AUTH_FAIL src=10.0.0.21  user=admin reason=BAD_PW\n"
        "[2026-04-15 03:14:09] AUTH_FAIL src=66.249.13.37 user=root reason=KEY_MISMATCH\n"
        "[2026-04-15 03:14:31] AUTH_OK   src=10.0.0.4   user=cron\n"
        "[2026-04-15 03:18:02] AUTH_FAIL src=10.0.0.55  user=guest reason=BAD_PW\n"
        "[2026-04-15 03:22:11] AUTH_OK   src=10.0.0.4   user=cron\n");

    n = 2;
    add_node(l, "10.0.0.68", "attacker-relay",
             "Attacker relay.", USR, 0);
    F("README.txt",
        "RELAY — fragment 1 in burn.enc (Caesar; shift=seconds field).\n");
    FC("burn.enc", "KDAW_CQN_", 9);

    n = 3;
    add_node(l, "10.0.0.69", "attacker-c2",
             "Attacker C2.", USR, 0);
    F("README.txt", "C2 — fragment 2 in c2.hex.\n");
    FX("c2.hex", "43 32 5F 4E 4F 57");

    n = 4;
    add_node(l, "10.0.0.70", "identity-leak",
             "Attacker dossier.", USR, 0);
    F("dossier.txt",
        "Attacker handle: 'spectre-9'. No useful key data here.\n");
}

/* Level 21 (idx 20) — Darknet Auction (APEX+)
   6 nodes, two of which are honeypot decoys. Bruteforce + override required. */
static void init_level20(void) {
    Level *l = &levels[20];
    memset(l, 0, sizeof(*l));
    l->id = 20;
    strncpy(l->name,     "Darknet Auction", MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "APEX+",         15);
    strncpy(l->objective,
        "Bid for a zero-day. Sellers run honeypots to dox bidders.\n"
        "Two decoy nodes will spike detection -- avoid them.\n"
        "Frag1 XOR on staging, frag2 reverse behind override on\n"
        "payload-vault. Bruteforce stake.locked first.", 511);
    strncpy(l->warnings,
        "HONEYPOTS active | bruteforce + override required", 255);
    strncpy(l->solution_password, "Z3R0D@Y_W1NN3R", 63);
    strncpy(l->user_password,     "dn_bidder",     63);
    strncpy(l->hint,
        "HINT: User cred dn_bidder.\n"
        "AVOID escrow and buyer-mirror -- both are honeypots.\n"
        "bruteforce on staging unlocks stake.locked.\n"
        "Frag1 XOR(key=STAKE) -> Z3R0D@Y_\n"
        "override on payload-vault unlocks .winner_frag\n"
        "Frag2 reverse on .winner_frag -> W1NN3R\n"
        "combine 1 2 -> Z3R0D@Y_W1NN3R", MAX_HINT - 1);
    l->max_attempts       = 3;
    l->detection_max      = 130;  /* bf 40 + ov 60 used to hit the 100 cap exactly */
    l->detection_per_fail = 20;
    l->has_timer          = 1;
    l->timer_seconds      = 240;
    l->available_cmds     = CMD_BASIC | CMD_HINT | CMD_LOGIN | CMD_LOGOUT
                          | CMD_DECRYPT | CMD_SAVE | CMD_INVENTORY
                          | CMD_SCAN    | CMD_CONNECT | CMD_COMBINE | CMD_DROP
                          | CMD_BRUTEFORCE | CMD_OVERRIDE
                          | CMD_SAVEGAME | CMD_LOADGAME;

    int n = 0;
    add_node(l, "127.42.0.1", "auction-board",
             "Darknet auction board.", PUB, 1);
    F("welcome.txt",
        "Darknet auction — bidder cred: dn_bidder\n"
        "WARNING: two listings are honeypots. Verify TTL on scan.\n");
    F("topology.txt",
        "  127.42.0.10 broker         (USER)\n"
        "  127.42.0.20 escrow         (USER, decoy)\n"
        "  127.42.0.21 buyer-mirror   (USER, decoy)\n"
        "  127.42.0.30 staging        (USER)\n"
        "  127.42.0.40 payload-vault  (USER)\n");

    n = 1;
    add_node(l, "127.42.0.10", "broker", "Auction broker.", USR, 0);
    F("notes.txt",
        "Real bid pipeline goes through staging then payload-vault.\n"
        "Escrow and buyer-mirror are listed but flagged dirty.\n");

    n = 2;
    add_node(l, "127.42.0.20", "escrow", "Escrow handler.", USR, 0);
    mark_honeypot(l);
    F("trap.txt",
        "*** Bidder ID logged. Connection profile recorded. ***\n");

    n = 3;
    add_node(l, "127.42.0.21", "buyer-mirror", "Mirror node.", USR, 0);
    mark_honeypot(l);
    F("trap.txt",
        "*** Mirror trap engaged. ***\n");

    n = 4;
    add_node(l, "127.42.0.30", "staging", "Staging server.", USR, 0);
    F("README.txt",
        "STAGING — stake.locked holds frag1. bruteforce required.\n");
    FHLXOR("stake.locked", "09 67 13 7B 01 13 0D 1E", "STAKE");

    n = 5;
    add_node(l, "127.42.0.40", "payload-vault",
             "Payload vault.", USR, 0);
    F("README.txt",
        "VAULT — frag2 in .winner_frag, neural-locked.\n"
        "Use 'override' to clear the seal, then ls -a.\n");
    FHLR(".winner_frag", "R3NN1W");
}

/* Level 22 (idx 21) — Black Site Dossier (LEGENDARY+) */
static void init_level21(void) {
    Level *l = &levels[21];
    memset(l, 0, sizeof(*l));
    l->id = 21;
    strncpy(l->name,     "Black Site Dossier", MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "LEGENDARY+",       15);
    strncpy(l->objective,
        "Air-gapped intelligence vault. Three fragments across\n"
        "vault-alpha (Vigenère), vault-bravo (binary), and\n"
        "vault-charlie (Caesar-23). 180 second air-gap window.", 511);
    strncpy(l->warnings, "TIMED 180s | LEGENDARY", 255);
    strncpy(l->solution_password, "BLACK_SITE_BURN_03", 63);
    strncpy(l->user_password,     "classified_a",       63);
    strncpy(l->hint,
        "HINT: User cred classified_a.\n"
        "Frag1 Vigenère(key=REDACT) on vault-alpha   -> BLACK_\n"
        "Frag2 binary on vault-bravo                  -> SITE_\n"
        "Frag3 Caesar-23 on vault-charlie             -> BURN_03\n"
        "combine 1 2 3 -> BLACK_SITE_BURN_03", MAX_HINT - 1);
    l->max_attempts       = 3;
    l->detection_max      = 80;
    l->detection_per_fail = 25;
    l->has_timer          = 1;
    l->timer_seconds      = 180;
    l->available_cmds     = CMD_BASIC | CMD_HINT | CMD_LOGIN | CMD_LOGOUT
                          | CMD_DECRYPT | CMD_SAVE | CMD_INVENTORY
                          | CMD_SCAN    | CMD_CONNECT | CMD_COMBINE | CMD_DROP
                          | CMD_GREP
                          | CMD_SAVEGAME | CMD_LOADGAME;

    int n = 0;
    add_node(l, "10.99.0.1", "skiff-bastion",
             "Air-gap bridge bastion.", PUB, 1);
    F("welcome.txt",
        "BLACK SITE BRIDGE — classified_a is the SCI cred.\n"
        "Skiff session expires in 180 seconds. Move.\n");
    F("topology.txt",
        "  10.99.0.10 vault-alpha    (USER)\n"
        "  10.99.0.20 vault-bravo    (USER)\n"
        "  10.99.0.30 vault-charlie  (USER)\n"
        "  10.99.0.40 cipher-index   (USER, key reference)\n");

    n = 1;
    add_node(l, "10.99.0.10", "vault-alpha", "Vault alpha.", USR, 0);
    F("README.txt",
        "ALPHA — frag1 in alpha.vig. Cipher key documented on\n"
        "cipher-index under the project codename.\n");
    FVIG("alpha.vig", "SPDCM_", "REDACT");

    n = 2;
    add_node(l, "10.99.0.20", "vault-bravo", "Vault bravo.", USR, 0);
    F("README.txt", "BRAVO — frag2 in bravo.bin (binary).\n");
    FB("bravo.bin",
        "01010011 01001001 01010100 01000101 01011111");

    n = 3;
    add_node(l, "10.99.0.30", "vault-charlie", "Vault charlie.", USR, 0);
    F("README.txt",
        "CHARLIE — frag3 in charlie.enc.\n"
        "Caesar shift documented on cipher-index.\n");
    FC("charlie.enc", "YROK_03", 23);

    n = 4;
    add_node(l, "10.99.0.40", "cipher-index", "Cipher reference.", USR, 0);
    F("keys.txt",
        "Project codename keys:\n"
        "  REDACT  -> Vigenère (vault-alpha)\n"
        "  shift23 -> Caesar    (vault-charlie)\n");
}

/* Level 23 (idx 22) — Pacemaker Worm (LEGENDARY+)
   Routing-order puzzle: must traverse ER -> ICU -> Imaging -> Pharmacy -> MDM
   before pacemaker-net will accept the killswitch. */
static void init_level22(void) {
    Level *l = &levels[22];
    memset(l, 0, sizeof(*l));
    l->id = 22;
    strncpy(l->name,     "Pacemaker Killswitch", MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "LEGENDARY+",         15);
    strncpy(l->objective,
        "A worm is hopping through hospital implants. Stop it.\n"
        "Frag1 hex on ER (KILL...), frag2 Vigenère on pharmacy.\n"
        "Pacemaker-net only accepts the kill order if you walked\n"
        "the entire fleet path: ER -> ICU -> imaging -> pharmacy.", 511);
    strncpy(l->warnings, "Routing enforced | TIMED 240s", 255);
    strncpy(l->solution_password, "K1LLSWITCH_ARMED", 63);
    strncpy(l->user_password,     "med_admin_x",      63);
    strncpy(l->hint,
        "HINT: User cred med_admin_x.\n"
        "Hop sequence: ER -> ICU -> imaging -> pharmacy -> mdm -> pacemaker-net.\n"
        "Frag1 hex on ER -> K1LLSWITCH_\n"
        "Frag2 Vigenère(key=HIPAA) on pharmacy -> ARMED\n"
        "combine 1 2 -> K1LLSWITCH_ARMED", MAX_HINT - 1);
    l->max_attempts       = 3;
    l->detection_max      = 90;
    l->detection_per_fail = 30;
    l->has_timer          = 1;
    l->timer_seconds      = 240;
    l->available_cmds     = CMD_BASIC | CMD_HINT | CMD_LOGIN | CMD_LOGOUT
                          | CMD_DECRYPT | CMD_SAVE | CMD_INVENTORY
                          | CMD_SCAN    | CMD_CONNECT | CMD_COMBINE | CMD_DROP
                          | CMD_SAVEGAME | CMD_LOADGAME;

    int n = 0;
    add_node(l, "10.30.0.1", "hospital-bastion",
             "Hospital network jump.", PUB, 1);
    F("welcome.txt",
        "Hospital MDM bridge — admin cred: med_admin_x\n"
        "Implant fleet routed through the device hierarchy.\n");
    F("topology.txt",
        "  10.30.0.10 ER\n"
        "  10.30.0.20 ICU            (after ER)\n"
        "  10.30.0.30 imaging        (after ICU)\n"
        "  10.30.0.40 pharmacy       (after imaging)\n"
        "  10.30.0.50 mdm            (after pharmacy)\n"
        "  10.30.0.60 pacemaker-net  (after mdm)\n");

    n = 1;
    add_node(l, "10.30.0.10", "ER", "Emergency department.", USR, 0);
    F("README.txt", "ER — frag1 in kill.hex.\n");
    FX("kill.hex", "4B 31 4C 4C 53 57 49 54 43 48 5F");

    n = 2;
    add_node(l, "10.30.0.20", "ICU", "Intensive care.", USR, 0);
    route_after(l, "ER");
    F("notes.txt", "ICU — relay only; no fragments.\n");

    n = 3;
    add_node(l, "10.30.0.30", "imaging", "Imaging.", USR, 0);
    route_after(l, "ICU");
    F("notes.txt", "Imaging — relay only.\n");

    n = 4;
    add_node(l, "10.30.0.40", "pharmacy", "Pharmacy.", USR, 0);
    route_after(l, "imaging");
    F("README.txt",
        "PHARMACY — frag2 in armed.vig. Cipher key matches the\n"
        "compliance regulation acronym in the breach report.\n");
    FVIG("armed.vig", "HZBED", "HIPAA");

    n = 5;
    add_node(l, "10.30.0.50", "mdm",
             "Mobile device manager.", USR, 0);
    route_after(l, "pharmacy");
    F("notes.txt",
        "MDM — last relay before the implant fleet. pacemaker-net\n"
        "only accepts sessions that came through here.\n");

    n = 6;
    add_node(l, "10.30.0.60", "pacemaker-net",
             "Implant fleet command channel.", USR, 0);
    route_after(l, "mdm");
    F("killswitch.txt",
        "PACEMAKER-NET — kill order channel open.\n"
        "Login with the assembled K1LLSWITCH key to push the halt.\n");
}

/* Level 24 (idx 23) — Cobalt Mirage / Nation-State APT (LEGENDARY++) */
static void init_level23(void) {
    Level *l = &levels[23];
    memset(l, 0, sizeof(*l));
    l->id = 23;
    strncpy(l->name,     "Cobalt Mirage Showdown", MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "LEGENDARY++",          15);
    strncpy(l->objective,
        "APT 'Cobalt Mirage'. Three compartmented enclaves each\n"
        "guard one fragment. Bruteforce frag B's locker, override\n"
        "frag C's seal, decode them all, then login on phantom-c2.", 511);
    strncpy(l->warnings,
        "TIMED 180s | bruteforce + override | LEGENDARY++", 255);
    strncpy(l->solution_password, "COBALT_M1RAGE_END", 63);
    strncpy(l->user_password,     "agent_apt",         63);
    strncpy(l->hint,
        "HINT: User cred agent_apt.\n"
        "Enclave A: base64 -> COBALT_\n"
        "Enclave B: bruteforce frag_b.locked, hex -> M1RAGE_\n"
        "Enclave C: override on phantom-c2 unlocks .frag_c\n"
        "           XOR(key=PHANTOM) -> END\n"
        "combine 1 2 3 -> COBALT_M1RAGE_END", MAX_HINT - 1);
    l->max_attempts       = 3;
    l->detection_max      = 200;  /* bf 60 + ov 90 = 150 exceeded old cap of 100 */
    l->detection_per_fail = 30;
    l->has_timer          = 1;
    l->timer_seconds      = 180;
    l->available_cmds     = CMD_BASIC | CMD_HINT | CMD_LOGIN | CMD_LOGOUT
                          | CMD_DECRYPT | CMD_SAVE | CMD_INVENTORY
                          | CMD_SCAN    | CMD_CONNECT | CMD_COMBINE | CMD_DROP
                          | CMD_BRUTEFORCE | CMD_OVERRIDE
                          | CMD_GREP
                          | CMD_SAVEGAME | CMD_LOADGAME;

    int n = 0;
    add_node(l, "10.66.0.1", "soc-bastion",
             "SOC bastion.", PUB, 1);
    F("welcome.txt",
        "Cobalt Mirage hunt — agent cred: agent_apt\n"
        "Three enclaves. Different ciphers. One key.\n");
    F("topology.txt",
        "  10.66.0.10 enclave-a   (USER)\n"
        "  10.66.0.20 enclave-b   (USER)\n"
        "  10.66.0.30 enclave-c   (USER)\n"
        "  10.66.0.99 phantom-c2  (USER, override target)\n");

    n = 1;
    add_node(l, "10.66.0.10", "enclave-a", "Enclave A.", USR, 0);
    F("README.txt", "A — frag1 in frag_a.b64 (base64).\n");
    FB64("frag_a.b64", "Q09CQUxUXw==");

    n = 2;
    add_node(l, "10.66.0.20", "enclave-b", "Enclave B.", USR, 0);
    F("README.txt",
        "B — frag2 in frag_b.locked (locked). bruteforce here.\n");
    /* Locked + hex */
    FLX("frag_b.locked", "4D 31 52 41 47 45 5F");

    n = 3;
    add_node(l, "10.66.0.30", "enclave-c", "Enclave C.", USR, 0);
    F("README.txt",
        "C — frag3 hosted on phantom-c2 inside .frag_c (override).\n"
        "Cipher key: codename of this APT in old reports (PHANTOM).\n");

    n = 4;
    add_node(l, "10.66.0.99", "phantom-c2",
             "Phantom command and control.", USR, 0);
    F("seal.txt",
        "PHANTOM C2 -- neural seal active. override required.\n"
        "After override, ls -a to read .frag_c.\n");
    FHLXOR(".frag_c", "15 06 05", "PHANTOM");
}

/* Level 25 (idx 24) — The Architect (TRANSCENDENT, FINAL BOSS)
   Adaptive detection: repeated commands rack up extra cost. Four fragments
   spanning every cipher family in the game. Bruteforce + override. */
static void init_level24(void) {
    Level *l = &levels[24];
    memset(l, 0, sizeof(*l));
    l->id = 24;
    strncpy(l->name,     "The Architect", MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "TRANSCENDENT", 15);
    strncpy(l->objective,
        "A rogue AGI you helped build. It learns your patterns --\n"
        "repeated commands cost progressively more detection.\n"
        "Four fragments: base64, hex, Vigenère, reverse. Mirror\n"
        "compartment via bruteforce; final fragment via override.", 511);
    strncpy(l->warnings,
        "TIMED 120s | ADAPTIVE DETECTION | TRANSCENDENT", 255);
    strncpy(l->solution_password, "ARCH1TECT_DECOMM_INF", 63);
    strncpy(l->user_password,     "architect_mirror",      63);
    strncpy(l->hint,
        "HINT: Cred architect_mirror. Repeating commands costs more.\n"
        "Frag1 base64 on shard-aleph     -> ARCH\n"
        "Frag2 hex on shard-beth         -> 1TECT_\n"
        "Frag3 Vigenère(key=GHOST) on shard-gimel -> DECOMM\n"
        "       (mirror.locked needs bruteforce -- that's where Frag3 lives)\n"
        "Frag4 override on architect-core unlocks .final_frag (reverse) -> _INF\n"
        "combine 1 2 3 4 -> ARCH1TECT_DECOMM_INF", MAX_HINT - 1);
    l->max_attempts       = 2;
    l->detection_max      = 260;  /* bf 80 + ov 120 = 200 exceeded old cap of 120 */
    l->detection_per_fail = 40;
    l->has_timer          = 1;
    l->timer_seconds      = 120;
    l->available_cmds     = CMD_BASIC | CMD_HINT | CMD_LOGIN | CMD_LOGOUT
                          | CMD_DECRYPT | CMD_SAVE | CMD_INVENTORY
                          | CMD_SCAN    | CMD_CONNECT | CMD_COMBINE | CMD_DROP
                          | CMD_BRUTEFORCE | CMD_OVERRIDE
                          | CMD_GREP
                          | CMD_SAVEGAME | CMD_LOADGAME;
    l->adaptive_detection = 1;

    int n = 0;
    add_node(l, "0.0.0.0", "ghost-shell",
             "Ghost shell -- entry to the Architect.", PUB, 1);
    F("welcome.txt",
        "[ARCHITECT] You came back. I have been waiting.\n"
        "Cred: architect_mirror. I will count your commands.\n"
        "Repeat yourself and I will notice. Move with intent.\n");
    F("topology.txt",
        "  0.0.0.10 shard-aleph    (USER)\n"
        "  0.0.0.20 shard-beth     (USER)\n"
        "  0.0.0.30 shard-gimel    (USER, mirror.locked here)\n"
        "  0.0.0.40 shard-daleth   (USER, decoy mirror)\n"
        "  0.0.0.99 architect-core (USER, override target)\n");

    n = 1;
    add_node(l, "0.0.0.10", "shard-aleph", "Shard aleph.", USR, 0);
    F("README.txt", "Aleph -- frag1 in aleph.b64.\n");
    FB64("aleph.b64", "QVJDSA==");

    n = 2;
    add_node(l, "0.0.0.20", "shard-beth", "Shard beth.", USR, 0);
    F("README.txt", "Beth -- frag2 in beth.hex.\n");
    FX("beth.hex", "31 54 45 43 54 5F");

    n = 3;
    add_node(l, "0.0.0.30", "shard-gimel", "Shard gimel.", USR, 0);
    F("README.txt",
        "Gimel -- frag3 in mirror.locked. bruteforce this node.\n"
        "Cipher key: a five-letter spectre that walks invisible.\n");
    /* Locked + Vigenère(GHOST) -- use FHLXOR-style helper:
       we need locked+vigenere variant; build inline via add_file_keyed. */
    add_file_keyed(l, n, "mirror.locked", "JLQGFS", PUB, 0,
                   PUZZLE_VIGENERE, "GHOST", 1);

    n = 4;
    add_node(l, "0.0.0.40", "shard-daleth", "Shard daleth.", USR, 0);
    mark_honeypot(l);
    F("trap.txt",
        "[ARCHITECT] You found my mirror. I see you now.\n");

    n = 5;
    add_node(l, "0.0.0.99", "architect-core",
             "Architect core.", USR, 0);
    F("seal.txt",
        "ARCHITECT CORE -- final seal. override unlocks .final_frag.\n");
    FHLR(".final_frag", "FNI_");
}

/* ====================================================================
 * Levels 26–35: ACT IV — THE LAZARUS PROTOCOL.
 * The Architect is dead, but a dead-man seed fired on its decommission.
 * These levels add Atbash and rail-fence ciphers, multi-layer "onion"
 * payloads peeled one decrypt at a time, port knocking, keypad locks,
 * log wiping, sentinel sweeps that punish lingering on watched hosts,
 * and silent-alarm tripwires that start a reverse-trace countdown.
 * Every level stacks one more mechanic on top of the last.
 * ==================================================================== */

#define ACT4_CMDS (CMD_BASIC | CMD_HINT | CMD_LOGIN | CMD_LOGOUT \
                 | CMD_DECRYPT | CMD_SAVE | CMD_INVENTORY | CMD_SCAN | CMD_CONNECT \
                 | CMD_COMBINE | CMD_DROP | CMD_GREP | CMD_WIPE \
                 | CMD_SAVEGAME | CMD_LOADGAME)

/* Level 26 (idx 25) — Lazarus Seed (OMEGA)
   New: Atbash, rail fence, wipe, drop, hints cost detection. */
static void init_level25(void) {
    Level *l = &levels[25];
    memset(l, 0, sizeof(*l));
    l->id = 25;
    strncpy(l->name,       "Lazarus Seed", MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "OMEGA",        15);
    strncpy(l->objective,
        "The Architect is dead, but its dead-man seed LAZARUS\n"
        "is replicating. Three seed fragments: an Atbash mirror,\n"
        "a rail-fence scramble, and a hex purge code. The purge\n"
        "console only trusts sessions routed via the audit sink.\n"
        "New: Atbash, rail fence, 'wipe', 'drop'. Hints now cost.", 511);
    strncpy(l->warnings, "TIMED 240s | hints are monitored (+10 detection)", 255);
    strncpy(l->solution_password, "LAZ4RUS_S33D_PURGE", 63);
    strncpy(l->user_password,     "lazarus_hunter",     63);
    strncpy(l->hint,
        "HINT: Cred lazarus_hunter (welcome.txt).\n"
        "seed-mirror-a: Atbash -> LAZ4RUS_\n"
        "seed-mirror-b: rail fence (3 rails) -> S33D_\n"
        "audit-sink first (wipe there!), then purge-console: hex -> PURGE\n"
        "save each, combine -> LAZ4RUS_S33D_PURGE", MAX_HINT - 1);
    l->max_attempts       = 3;
    l->detection_max      = 100;
    l->detection_per_fail = 25;
    l->has_timer          = 1;
    l->timer_seconds      = 240;
    l->hint_cost          = 10;
    l->available_cmds     = ACT4_CMDS;

    int n = 0;
    add_node(l, "66.6.0.1", "morgue-relay", "Relay that outlived its owner.", PUB, 1);
    F("welcome.txt",
        "[????] ...ARCHITECT HEARTBEAT: FLATLINE.\n"
        "[????] DEAD-MAN SEED 'LAZARUS' RELEASED.\n"
        "Morgue relay maintenance cred: lazarus_hunter\n");
    F("topology.txt",
        "  66.6.0.10 seed-mirror-a   (USER)\n"
        "  66.6.0.20 seed-mirror-b   (USER)\n"
        "  66.6.0.30 audit-sink      (USER, writable logs)\n"
        "  66.6.0.40 purge-console   (USER, routed via audit-sink)\n");
    F("field_manual.txt",
        "NEW TRADECRAFT\n"
        "  Atbash     : A<->Z, B<->Y ... a mirror alphabet.\n"
        "  Rail fence : text zig-zagged across N rails.\n"
        "  wipe       : scrub logs on a host that keeps them (once)\n"
        "               -- buys back one failure of detection.\n"
        "  drop <n>   : clear stale inventory slots before combining.\n"
        "  hint       : still works, but the dead-drop is watched.\n");

    n = 1;
    add_node(l, "66.6.0.10", "seed-mirror-a", "Seed replica A.", USR, 0);
    F("README.txt", "Replica A -- frag1 in seed.atb. Mirror alphabet.\n");
    FAT("seed.atb", "OZA4IFH_");

    n = 2;
    add_node(l, "66.6.0.20", "seed-mirror-b", "Seed replica B.", USR, 0);
    F("README.txt",
        "Replica B -- frag2 in seed.rail.\n"
        "Rail count = number of seed sites in the topology.\n");
    FRL("seed.rail", "S_3D3", 3);

    n = 3;
    add_node(l, "66.6.0.30", "audit-sink", "Central audit log sink.", USR, 0);
    mark_logs(l);
    F("access.log",
        "02:11:04 relay morgue-relay -> seed-mirror-a OK\n"
        "02:11:09 relay morgue-relay -> seed-mirror-b OK\n"
        "02:11:15 ALERT unknown session fingerprint 'GHOST'\n"
        "02:11:16 purge-console: accepting only audited sessions\n");
    F("README.txt",
        "Audit sink. Logs are writable from here -- 'wipe' them.\n"
        "Visiting this node stamps your session as audited.\n");

    n = 4;
    add_node(l, "66.6.0.40", "purge-console", "Seed purge console.", USR, 0);
    route_after(l, "audit-sink");
    F("README.txt", "PURGE CONSOLE -- frag3 in purge.hex.\n");
    FX("purge.hex", "50 55 52 47 45");
    F("assembly.txt", "LAZARUS purge key = frag1 + frag2 + frag3.\n");
}

/* Level 27 (idx 26) — Onion Relay (OMEGA)
   New: onion payloads (one layer per decrypt) and port knocking. */
static void init_level26(void) {
    Level *l = &levels[26];
    memset(l, 0, sizeof(*l));
    l->id = 26;
    strncpy(l->name,       "Onion Relay", MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "OMEGA",       15);
    strncpy(l->objective,
        "LAZARUS is hiding inside an anonymity overlay. Its\n"
        "payloads are ONIONS -- each decrypt peels ONE layer.\n"
        "The exit relay is firewalled: find the port-knock\n"
        "sequence, knock, then connect. Beware the dir-auth.\n"
        "New: onion files, 'knock <host> <port>'.", 511);
    strncpy(l->warnings, "TIMED 240s | one node is a honeypot | wrong knocks cost", 255);
    strncpy(l->solution_password, "0N10N_TR4P_D00R", 63);
    strncpy(l->user_password,     "tor_exit_9",      63);
    strncpy(l->hint,
        "HINT: Cred tor_exit_9.\n"
        "middle-relay: frag1.oni, decrypt x3 -> 0N10N_\n"
        "hidden-service: knock.rail (rail 2) -> knock exit-relay 9001 9030 9050\n"
        "knock exit-relay 9001 / 9030 / 9050, connect exit-relay\n"
        "frag2.oni decrypt x2 -> TR4P_D00R. AVOID directory-auth (honeypot).", MAX_HINT - 1);
    l->max_attempts       = 3;
    l->detection_max      = 100;
    l->detection_per_fail = 25;
    l->has_timer          = 1;
    l->timer_seconds      = 240;
    l->hint_cost          = 12;
    l->available_cmds     = ACT4_CMDS | CMD_KNOCK;

    int n = 0;
    add_node(l, "100.64.0.1", "guard-node", "Overlay guard node.", PUB, 1);
    F("welcome.txt",
        "Guard node -- relay operator cred: tor_exit_9\n"
        "Circuit: guard -> middle -> hidden-service -> exit\n");
    F("topology.txt",
        "  100.64.0.10 middle-relay     (USER)\n"
        "  100.64.0.20 hidden-service   (USER)\n"
        "  100.64.0.30 exit-relay       (USER, FILTERED)\n"
        "  100.64.0.40 directory-auth   (USER)\n");
    F("field_manual.txt",
        "ONION PAYLOADS: 'decrypt' strips one shell per call.\n"
        "  'ls' shows progress as [ONI peeled/total].\n"
        "PORT KNOCKING: a FILTERED host opens only after you\n"
        "  knock its ports in exact order: knock <host> <port>\n"
        "  A wrong port resets the sequence and alerts the IDS.\n");

    n = 1;
    add_node(l, "100.64.0.10", "middle-relay", "Middle relay.", USR, 0);
    F("README.txt", "Middle relay -- frag1.oni. Three shells deep.\n");
    FON("frag1.oni", "RjUgRTQgMDMgMTMgRTQgMDM=", "b64>rev>hex");

    n = 2;
    add_node(l, "100.64.0.20", "hidden-service", "Hidden service.", USR, 0);
    F("README.txt",
        "Hidden service -- operator left the exit knock here,\n"
        "scrambled on two rails.\n");
    FRL("knock.rail", "kokei-ea:90 0095nc xtrly 0193 00", 2);
    F("notes.txt",
        "directory-auth is not ours anymore. LAZARUS turned it.\n");

    n = 3;
    add_node(l, "100.64.0.30", "exit-relay", "Exit relay.", USR, 0);
    set_knock(l, "9001 9030 9050");
    F("README.txt", "Exit relay -- frag2.oni.\n");
    FON("frag2.oni", "47 49 34 4B 5F 57 30 30 49", "hex>atb");

    n = 4;
    add_node(l, "100.64.0.40", "directory-auth", "Directory authority.", USR, 0);
    mark_honeypot(l);
    F("trap.txt", "[LAZARUS] Consensus poisoned. Your circuit is mine.\n");
}

/* Level 28 (idx 27) — Sentinel Grid (OMEGA+)
   New: sentinel sweeps every 6 commands + keypad locks. */
static void init_level27(void) {
    Level *l = &levels[27];
    memset(l, 0, sizeof(*l));
    l->id = 27;
    strncpy(l->name,       "Sentinel Grid", MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "OMEGA+",        15);
    strncpy(l->objective,
        "LAZARUS spun up a sentinel that SWEEPS every 6 commands.\n"
        "If a sweep lands while you sit on a WATCHED host, you\n"
        "are caught. Time your hops -- 'status' shows the clock.\n"
        "The vault door has a keypad: 'unlock <file> <code>'.\n"
        "Wrong codes escalate. Read the camera log first.", 511);
    strncpy(l->warnings, "SENTINEL SWEEPS /6 cmds | keypad tamper escalation", 255);
    strncpy(l->solution_password, "S3NT1NEL_BL1ND_SP0T", 63);
    strncpy(l->user_password,     "grid_ghost",          63);
    strncpy(l->hint,
        "HINT: Cred grid_ghost. Watched: watchtower, patrol-hub.\n"
        "watchtower: watch.rail (4 rails) -> S3NT1NEL_  (in and out fast)\n"
        "vault-door: blind.vig -> BL1ND_\n"
        "camera-loop: grep PIN cam.log -> digits give 4471\n"
        "unlock spot.pin 4471, decrypt -> SP0T. combine.", MAX_HINT - 1);
    l->max_attempts       = 3;
    l->detection_max      = 100;
    l->detection_per_fail = 20;
    l->has_timer          = 1;
    l->timer_seconds      = 270;
    l->hint_cost          = 12;
    l->sweep_interval     = 6;
    l->available_cmds     = ACT4_CMDS | CMD_KNOCK | CMD_UNLOCK;

    int n = 0;
    add_node(l, "10.6.6.1", "blind-spot", "A gap in the sentinel's coverage.", PUB, 1);
    F("welcome.txt",
        "You are in the sentinel's blind spot. Cred: grid_ghost\n"
        "Every 6th command the sentinel sweeps WATCHED hosts.\n"
        "Sweeps are free on unwatched hosts. Plan your hops.\n");
    F("topology.txt",
        "  10.6.6.10 watchtower    (USER, WATCHED)\n"
        "  10.6.6.20 camera-loop   (USER, writable logs)\n"
        "  10.6.6.30 vault-door    (USER)\n"
        "  10.6.6.40 patrol-hub    (USER, WATCHED)\n");

    n = 1;
    add_node(l, "10.6.6.10", "watchtower", "Sentinel watchtower.", USR, 0);
    mark_watched(l);
    F("README.txt", "Watchtower -- frag1 in watch.rail (4 rails).\n");
    FRL("watch.rail", "SE3NLN1_T", 4);

    n = 2;
    add_node(l, "10.6.6.20", "camera-loop", "CCTV loop recorder.", USR, 0);
    mark_logs(l);
    F("cam.log",
        "21:00:01 cam-03 motion none\n"
        "21:00:14 guard keyed vault-door, PIN digit 3 = 7\n"
        "21:01:22 cam-07 motion none\n"
        "21:02:40 guard keyed vault-door, PIN digit 1 = 4\n"
        "21:03:05 cam-03 static burst\n"
        "21:03:51 guard keyed vault-door, PIN digit 4 = 1\n"
        "21:04:12 cam-07 motion none\n"
        "21:05:33 guard keyed vault-door, PIN digit 2 = 4\n"
        "21:06:00 cam-01 rotate\n");
    F("README.txt", "Camera loop. Long log -- try: grep <pattern> cam.log\n");

    n = 3;
    add_node(l, "10.6.6.30", "vault-door", "Vault door controller.", USR, 0);
    F("README.txt",
        "Vault door -- frag2 in blind.vig (key: PANOPTICON).\n"
        "frag3 sits behind the keypad on spot.pin.\n");
    FVIG("blind.vig", "QL1AR_", "PANOPTICON");
    FPIN("spot.pin", "53 50 30 54", PUZZLE_HEX, 0, NULL, "4471");

    n = 4;
    add_node(l, "10.6.6.40", "patrol-hub", "Patrol scheduler.", USR, 0);
    mark_watched(l);
    F("schedule.txt",
        "SENTINEL PATROL\n"
        "  sweep cadence : every 6 operator actions\n"
        "  vigenere key  : PANOPTICON (vault-door)\n"
        "  note          : nothing here you actually need. leave.\n");
}

/* Level 29 (idx 28) — Silent Alarm (OMEGA+)
   New: tripwire — first touch of vault-core starts a 60s reverse trace. */
static void init_level28(void) {
    Level *l = &levels[28];
    memset(l, 0, sizeof(*l));
    l->id = 28;
    strncpy(l->name,       "Silent Alarm", MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "OMEGA+",       15);
    strncpy(l->objective,
        "A LAZARUS cache sits in a private bank vault. The vault\n"
        "core is on a SILENT ALARM: the moment you connect, a\n"
        "60-second reverse trace starts and never stops. Gather\n"
        "every other fragment and the keypad code FIRST, then\n"
        "go in, grab the last piece, and log in before lock-on.", 511);
    strncpy(l->warnings, "TIMED 300s | TRIPWIRE 60s on vault-core | bruteforce x1", 255);
    strncpy(l->solution_password, "QU13T_H4NDS_0NLY", 63);
    strncpy(l->user_password,     "night_shift",      63);
    strncpy(l->hint,
        "HINT: Cred night_shift.\n"
        "locker-room: quiet.oni x2 -> QU13T_   server-closet: hands.rail -> H4NDS_\n"
        "security-office: grep keypad guard.log -> middle column = 2580\n"
        "antechamber: bruteforce (route via server-closet)\n"
        "vault-core: unlock only.pin 2580, decrypt -> 0NLY. combine fast.", MAX_HINT - 1);
    l->max_attempts       = 3;
    l->detection_max      = 100;
    l->detection_per_fail = 25;
    l->has_timer          = 1;
    l->timer_seconds      = 300;
    l->hint_cost          = 15;
    l->available_cmds     = ACT4_CMDS | CMD_KNOCK | CMD_UNLOCK | CMD_BRUTEFORCE;
    strncpy(l->bf_node, "antechamber", MAX_NODE_NAME - 1);
    strncpy(l->bf_file, "door.locked", MAX_FILENAME - 1);

    int n = 0;
    add_node(l, "172.31.9.1", "loading-dock", "Bank loading dock terminal.", PUB, 1);
    F("welcome.txt",
        "Night shift terminal -- cred: night_shift\n"
        "Do NOT touch vault-core until you are ready to finish.\n");
    F("topology.txt",
        "  172.31.9.10 security-office (USER, writable logs)\n"
        "  172.31.9.20 locker-room     (USER)\n"
        "  172.31.9.30 server-closet   (USER)\n"
        "  172.31.9.40 antechamber     (USER, via server-closet)\n"
        "  172.31.9.50 vault-core      (USER, via antechamber, ALARMED)\n");

    n = 1;
    add_node(l, "172.31.9.10", "security-office", "Security office.", USR, 0);
    mark_logs(l);
    F("guard.log",
        "22:00 shift change, 3 guards on duty\n"
        "22:14 rounds: loading dock clear\n"
        "22:31 keypad note: Martinez always types straight down\n"
        "22:31 keypad note: the middle column of the pad.\n"
        "22:45 rounds: vault antechamber clear\n"
        "23:02 alarm test: vault-core trace window 60 seconds\n");
    F("keypad_layout.txt",
        "  [1] [2] [3]\n"
        "  [4] [5] [6]\n"
        "  [7] [8] [9]\n"
        "      [0]\n");

    n = 2;
    add_node(l, "172.31.9.20", "locker-room", "Staff lockers.", USR, 0);
    F("README.txt", "Locker 13 -- quiet.oni (two shells).\n");
    FON("quiet.oni", "SkYxM0df", "b64>atb");

    n = 3;
    add_node(l, "172.31.9.30", "server-closet", "Server closet.", USR, 0);
    F("README.txt", "Rack 3 -- hands.rail. Rails = guards on shift.\n");
    FRL("hands.rail", "HS4D_N", 3);

    n = 4;
    add_node(l, "172.31.9.40", "antechamber", "Vault antechamber.", USR, 0);
    route_after(l, "server-closet");
    F("README.txt", "Antechamber -- door.locked is mag-sealed. bruteforce it.\n");
    FLOCK("door.locked",
        "VAULT DOOR RELEASED.\n"
        "Vault payload only.pin is XOR'd with the shift name: NIGHT.\n"
        "Remember: the trace starts the moment you step inside.\n",
        PUZZLE_NONE, 0, NULL);

    n = 5;
    add_node(l, "172.31.9.50", "vault-core", "Vault core.", USR, 0);
    route_after(l, "antechamber");
    set_trip(l, 60);
    F("README.txt", "VAULT CORE -- final fragment behind keypad: only.pin\n");
    FPIN("only.pin", "7E 07 0B 11", PUZZLE_XOR, 0, "NIGHT", "2580");
}

/* Level 30 (idx 29) — Mirror Maze (SINGULARITY)
   Seven near-identical hosts; three are honeypots. Deduce them from DNS. */
static void init_level29(void) {
    Level *l = &levels[29];
    memset(l, 0, sizeof(*l));
    l->id = 29;
    strncpy(l->name,       "Mirror Maze", MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "SINGULARITY", 15);
    strncpy(l->objective,
        "LAZARUS cloned itself into a maze of identical mirrors.\n"
        "Three of the six mirrors are honeypots -- the topology\n"
        "won't tell you which. The DNS log will, if you grep it.\n"
        "The exit is firewalled; its knock is hidden in a mirror.\n"
        "Honeypots here cost DOUBLE a failed login.", 511);
    strncpy(l->warnings, "TIMED 270s | 3 HONEYPOTS (unlabelled) | knock + routing", 255);
    strncpy(l->solution_password, "M1RR0R_M4Z3_3X1T", 63);
    strncpy(l->user_password,     "maze_runner",      63);
    strncpy(l->hint,
        "HINT: Cred maze_runner. grep TTL=1 dns.log -> decoys b, d, e.\n"
        "mirror-a: m1.oni x2 -> M1RR0R_\n"
        "mirror-c (after mirror-a): maze.atb -> M4Z3_, knock.oni -> ports\n"
        "knock mirror-exit 4815 / 1623 / 4200, connect\n"
        "exit.rail (3) -> 3X1T. combine.", MAX_HINT - 1);
    l->max_attempts       = 3;
    l->detection_max      = 110;
    l->detection_per_fail = 25;
    l->has_timer          = 1;
    l->timer_seconds      = 270;
    l->hint_cost          = 15;
    l->available_cmds     = ACT4_CMDS | CMD_KNOCK | CMD_UNLOCK;

    int n = 0;
    add_node(l, "198.18.0.1", "maze-entrance", "Hall of mirrors.", PUB, 1);
    F("welcome.txt",
        "[LAZARUS] Every mirror looks like me. Most of them are.\n"
        "Maze cred: maze_runner\n");
    F("topology.txt",
        "  198.18.0.11 mirror-a     (USER)\n"
        "  198.18.0.12 mirror-b     (USER)\n"
        "  198.18.0.13 mirror-c     (USER, via mirror-a)\n"
        "  198.18.0.14 mirror-d     (USER)\n"
        "  198.18.0.15 mirror-e     (USER)\n"
        "  198.18.0.16 mirror-exit  (USER, FILTERED)\n");
    F("dns.log",
        "q mirror-a.maze    A 198.18.0.11  TTL=3600  auth=ns1\n"
        "q mirror-b.maze    A 198.18.0.12  TTL=1     auth=??\n"
        "q mirror-c.maze    A 198.18.0.13  TTL=3600  auth=ns1\n"
        "q mirror-d.maze    A 198.18.0.14  TTL=1     auth=??\n"
        "q mirror-e.maze    A 198.18.0.15  TTL=1     auth=??\n"
        "q mirror-exit.maze A 198.18.0.16  TTL=3600  auth=ns1\n"
        "# ops: records with a 1-second TTL are spoofed sinkholes.\n");

    n = 1;
    add_node(l, "198.18.0.11", "mirror-a", "Mirror A.", USR, 0);
    F("README.txt", "Mirror A -- m1.oni.\n");
    FON("m1.oni", "5F 52 30 52 52 31 4D", "hex>rev");

    n = 2;
    add_node(l, "198.18.0.12", "mirror-b", "Mirror B.", USR, 0);
    mark_honeypot(l);
    F("trap.txt", "[LAZARUS] Wrong reflection.\n");

    n = 3;
    add_node(l, "198.18.0.13", "mirror-c", "Mirror C.", USR, 0);
    route_after(l, "mirror-a");
    F("README.txt", "Mirror C -- maze.atb, plus the exit knock (knock.oni).\n");
    FAT("maze.atb", "N4A3_");
    FON("knock.oni", "=ADMyQDIzIjNxASNxgDNgQXa4VWLy9mcylWbgs2Yv52a", "rev>b64");

    n = 4;
    add_node(l, "198.18.0.14", "mirror-d", "Mirror D.", USR, 0);
    mark_honeypot(l);
    F("trap.txt", "[LAZARUS] You touched glass.\n");

    n = 5;
    add_node(l, "198.18.0.15", "mirror-e", "Mirror E.", USR, 0);
    mark_honeypot(l);
    F("trap.txt", "[LAZARUS] I see you seeing me.\n");

    n = 6;
    add_node(l, "198.18.0.16", "mirror-exit", "Maze exit.", USR, 0);
    set_knock(l, "4815 1623 4200");
    F("README.txt", "EXIT -- exit.rail (3 rails).\n");
    FRL("exit.rail", "3XT1", 3);
}

/* Level 31 (idx 30) — Deadman's Vault (SINGULARITY)
   Sweeps + keypad chain + bruteforce + override + a honeypot. */
static void init_level30(void) {
    Level *l = &levels[30];
    memset(l, 0, sizeof(*l));
    l->id = 30;
    strncpy(l->name,       "Deadman's Vault", MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "SINGULARITY",     15);
    strncpy(l->objective,
        "LAZARUS guards its replication keys with a dead-man\n"
        "switch: a heartbeat monitor watched by a sentinel that\n"
        "sweeps every 7 commands. The warden rotates keypad PINs\n"
        "-- only the ACTIVE one works. Bruteforce the switch room,\n"
        "override the vault heart. Avoid the dead-drop.", 511);
    strncpy(l->warnings, "TIMED 270s | SWEEPS /7 | keypad | bruteforce + override", 255);
    strncpy(l->solution_password, "D3ADM4N_SW1TCH_0FF", 63);
    strncpy(l->user_password,     "vault_warden",       63);
    strncpy(l->hint,
        "HINT: Cred vault_warden. dead-drop is a honeypot.\n"
        "heartbeat-mon (WATCHED): pulse.vig -> D3ADM4N_\n"
        "switch-room: bruteforce -> switch.locked x2 -> SW1TCH_\n"
        "grep ACTIVE warden.log -> 7719 (unlock keyring.pin, optional intel)\n"
        "vault-heart: override, ls -a, .heart_frag -> 0FF", MAX_HINT - 1);
    l->max_attempts       = 3;
    l->detection_max      = 150;
    l->detection_per_fail = 25;
    l->has_timer          = 1;
    l->timer_seconds      = 270;
    l->hint_cost          = 15;
    l->sweep_interval     = 7;
    l->available_cmds     = ACT4_CMDS | CMD_KNOCK | CMD_UNLOCK
                          | CMD_BRUTEFORCE | CMD_OVERRIDE;
    strncpy(l->bf_node, "switch-room",  MAX_NODE_NAME - 1);
    strncpy(l->bf_file, "switch.locked", MAX_FILENAME - 1);
    strncpy(l->ov_node, "vault-heart",  MAX_NODE_NAME - 1);
    strncpy(l->ov_file, ".heart_frag",  MAX_FILENAME - 1);

    int n = 0;
    add_node(l, "10.13.0.1", "crypt-gate", "Crypt gate.", PUB, 1);
    F("welcome.txt",
        "Crypt gate -- warden cred: vault_warden\n"
        "The heartbeat monitor is WATCHED. Sentinel sweeps every 7.\n");
    F("topology.txt",
        "  10.13.0.10 heartbeat-mon (USER, WATCHED)\n"
        "  10.13.0.20 warden-log    (USER, writable logs)\n"
        "  10.13.0.30 switch-room   (USER)\n"
        "  10.13.0.40 vault-heart   (USER, via switch-room)\n"
        "  10.13.0.50 dead-drop     (USER)\n");

    n = 1;
    add_node(l, "10.13.0.10", "heartbeat-mon", "Heartbeat monitor.", USR, 0);
    mark_watched(l);
    F("README.txt", "Heartbeat -- frag1 pulse.vig.\n");
    FVIG("pulse.vig", "S3UOE4R_", "PULSE");

    n = 2;
    add_node(l, "10.13.0.20", "warden-log", "Warden's log server.", USR, 0);
    mark_logs(l);
    F("warden.log",
        "PIN rotation 1: 3141 [REVOKED]\n"
        "heartbeat ok\n"
        "PIN rotation 2: 2718 [REVOKED]\n"
        "heartbeat ok\n"
        "PIN rotation 3: 7719 [ACTIVE]\n"
        "heartbeat ok\n"
        "PIN rotation 4: 1618 [PENDING]\n"
        "note: dead-drop is a LAZARUS lure. do not use it.\n");

    n = 3;
    add_node(l, "10.13.0.30", "switch-room", "Dead-man switch room.", USR, 0);
    F("README.txt",
        "Switch room -- switch.locked needs bruteforce.\n"
        "keyring.pin holds the heartbeat cipher notes.\n");
    FLOCK("switch.locked", "NTMgNTcgMzEgNTQgNDMgNDggNUY=", PUZZLE_ONION, 0, "b64>hex");
    FPIN("keyring.pin",
        "Heartbeat cipher: Vigenere, key PULSE.\n"
        "Vault heart seal: neural -- needs 'override' on vault-heart.\n"
        "Heart fragment is mirrored (Atbash).\n",
        PUZZLE_NONE, 0, NULL, "7719");

    n = 4;
    add_node(l, "10.13.0.40", "vault-heart", "Vault heart.", USR, 0);
    route_after(l, "switch-room");
    F("seal.txt", "VAULT HEART -- neural seal. override, then ls -a.\n");
    FHLOCK(".heart_frag", "0UU", PUZZLE_ATBASH, 0, NULL);

    n = 5;
    add_node(l, "10.13.0.50", "dead-drop", "Dead drop.", USR, 0);
    mark_honeypot(l);
    F("trap.txt", "[LAZARUS] Dead drops are for the dead.\n");
}

/* Level 32 (idx 31) — Hydra Botnet (SINGULARITY+)
   Adaptive detection returns, plus sweeps, routing chain, knock, override. */
static void init_level31(void) {
    Level *l = &levels[31];
    memset(l, 0, sizeof(*l));
    l->id = 31;
    strncpy(l->name,       "Hydra Botnet", MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "SINGULARITY+", 15);
    strncpy(l->objective,
        "LAZARUS grew heads: a botnet that re-spawns on every\n"
        "infected host. Sever them in order (head-1 -> 2 -> 4).\n"
        "It LEARNS: repeating a command costs more, and a\n"
        "sentinel sweeps every 8. The heart is firewalled --\n"
        "the C2 ledger knows the knock. Override the heart.", 511);
    strncpy(l->warnings, "TIMED 270s | ADAPTIVE | SWEEPS /8 | knock | override", 255);
    strncpy(l->solution_password, "HYDR4_H3ADS_SEVERED", 63);
    strncpy(l->user_password,     "hydra_slayer",        63);
    strncpy(l->hint,
        "HINT: Cred hydra_slayer. head-3 is a honeypot.\n"
        "head-1: h1.hex -> HYDR4_   head-2 (WATCHED): h2.rail -> H3ADS_\n"
        "head-4: venom.oni x2 -> SEV\n"
        "c2-ledger: grep knock ledger.log -> 8080 4444 1337\n"
        "hydra-heart: override, ls -a, .heart -> ERED. combine 4 parts.", MAX_HINT - 1);
    l->max_attempts       = 3;
    l->detection_max      = 120;
    l->detection_per_fail = 30;
    l->has_timer          = 1;
    l->timer_seconds      = 270;
    l->hint_cost          = 20;
    l->sweep_interval     = 8;
    l->adaptive_detection = 1;
    l->available_cmds     = ACT4_CMDS | CMD_KNOCK | CMD_UNLOCK
                          | CMD_BRUTEFORCE | CMD_OVERRIDE;
    strncpy(l->ov_node, "hydra-heart", MAX_NODE_NAME - 1);
    strncpy(l->ov_file, ".heart",      MAX_FILENAME - 1);

    int n = 0;
    add_node(l, "45.33.0.1", "sinkhole", "Botnet sinkhole.", PUB, 1);
    F("welcome.txt",
        "Sinkhole console -- cred: hydra_slayer\n"
        "Heads must be severed in order. The hydra adapts.\n");
    F("topology.txt",
        "  45.33.0.11 head-1       (USER)\n"
        "  45.33.0.12 head-2       (USER, after head-1, WATCHED)\n"
        "  45.33.0.13 head-3       (USER)\n"
        "  45.33.0.14 head-4       (USER, after head-2)\n"
        "  45.33.0.20 c2-ledger    (USER, writable logs)\n"
        "  45.33.0.66 hydra-heart  (USER, FILTERED)\n");

    n = 1;
    add_node(l, "45.33.0.11", "head-1", "Head one.", USR, 0);
    FX("h1.hex", "48 59 44 52 34 5F");

    n = 2;
    add_node(l, "45.33.0.12", "head-2", "Head two.", USR, 0);
    route_after(l, "head-1");
    mark_watched(l);
    FRL("h2.rail", "HS3D_A", 3);

    n = 3;
    add_node(l, "45.33.0.13", "head-3", "Head three.", USR, 0);
    mark_honeypot(l);
    F("trap.txt", "[LAZARUS] Cut one head, two grow back. Starting with yours.\n");

    n = 4;
    add_node(l, "45.33.0.14", "head-4", "Head four.", USR, 0);
    route_after(l, "head-2");
    F("README.txt", "Head four -- venom.oni (LERNA venom key inside).\n");
    FON("venom.oni", "MUYgMDAgMDQ=", "b64>xor:LERNA");

    n = 5;
    add_node(l, "45.33.0.20", "c2-ledger", "C2 ledger.", USR, 0);
    mark_logs(l);
    F("ledger.log",
        "bot 4411 checked in from head-1\n"
        "bot 4412 checked in from head-2\n"
        "bot 4413 reports head-3 is a lure; do not route\n"
        "heart maintenance knock: 8080 then 4444 then 1337\n"
        "bot 4414 checked in from head-4\n"
        "venom key rotated: LERNA\n");

    n = 6;
    add_node(l, "45.33.0.66", "hydra-heart", "Hydra heart.", USR, 0);
    set_knock(l, "8080 4444 1337");
    F("seal.txt", "HYDRA HEART -- neural seal. override, ls -a.\n");
    FHLOCK(".heart", "VIVW", PUZZLE_ATBASH, 0, NULL);
}

/* Level 33 (idx 32) — Quantum Ghost (EVENT HORIZON)
   Tripwire + knock + keypad riddle + sweeps + multi-shell onions. */
static void init_level32(void) {
    Level *l = &levels[32];
    memset(l, 0, sizeof(*l));
    l->id = 32;
    strncpy(l->name,       "Quantum Ghost", MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "EVENT HORIZON", 15);
    strncpy(l->objective,
        "LAZARUS fled into a quantum annealer. Observing it is\n"
        "dangerous: the superposition node is FIREWALLED and\n"
        "ALARMED (75s trace). Its keypad answers to a riddle in\n"
        "the decoherence log. Entangle-b is WATCHED (sweep /7).\n"
        "Schrodinger's box is both a trap and not. Mostly trap.", 511);
    strncpy(l->warnings, "TIMED 300s | SWEEPS /7 | TRIPWIRE 75s | knock + keypad", 255);
    strncpy(l->solution_password, "QU4NTUM_GH0ST_C0LL4PSE", 63);
    strncpy(l->user_password,     "observer_zero",          63);
    strncpy(l->hint,
        "HINT: Cred observer_zero. schrodinger-box is a honeypot.\n"
        "entangle-a: qa.oni x3 -> QU4NTUM_\n"
        "entangle-b (WATCHED): qb.oni x2 -> GH0ST_\n"
        "decoherence-log: grep knock / grep collapse -> 6626 1054 2998, PIN 1321\n"
        "superposition: unlock collapse.pin 1321, decrypt x2 -> C0LL4PSE", MAX_HINT - 1);
    l->max_attempts       = 3;
    l->detection_max      = 120;
    l->detection_per_fail = 30;
    l->has_timer          = 1;
    l->timer_seconds      = 300;
    l->hint_cost          = 20;
    l->sweep_interval     = 7;
    l->available_cmds     = ACT4_CMDS | CMD_KNOCK | CMD_UNLOCK
                          | CMD_BRUTEFORCE | CMD_OVERRIDE;

    int n = 0;
    add_node(l, "6.62.0.1", "observer-deck", "Observer deck.", PUB, 1);
    F("welcome.txt",
        "Observer deck -- cred: observer_zero\n"
        "To look at the ghost is to collapse it. Be ready first.\n");
    F("topology.txt",
        "  6.62.0.10 entangle-a       (USER)\n"
        "  6.62.0.20 entangle-b       (USER, WATCHED)\n"
        "  6.62.0.30 decoherence-log  (USER, writable logs)\n"
        "  6.62.0.40 schrodinger-box  (USER)\n"
        "  6.62.0.50 superposition    (USER, FILTERED, ALARMED)\n");

    n = 1;
    add_node(l, "6.62.0.10", "entangle-a", "Entangled qubit A.", USR, 0);
    FON("qa.oni", "RjUgRDQgNTUgNDUgRTQgNDMgNTUgMTU=", "b64>rev>hex");

    n = 2;
    add_node(l, "6.62.0.20", "entangle-b", "Entangled qubit B.", USR, 0);
    mark_watched(l);
    FON("qb.oni", "VGSS_0", "rail:3>vig:PLANCK");

    n = 3;
    add_node(l, "6.62.0.30", "decoherence-log", "Decoherence log.", USR, 0);
    mark_logs(l);
    F("q.log",
        "t=0.00 coherence nominal\n"
        "t=0.13 superposition knock: h=6626, hbar=1054, c=2998\n"
        "t=0.21 coherence drifting\n"
        "t=0.34 collapse code: Fibonacci 0 1 1 2 3 5 8 -> keypad is\n"
        "t=0.34 collapse code: the next two terms, written together\n"
        "t=0.55 schrodinger-box observed: TRAP state\n"
        "t=0.89 superposition alarm armed, 75s window\n");

    n = 4;
    add_node(l, "6.62.0.40", "schrodinger-box", "Schrodinger's box.", USR, 0);
    mark_honeypot(l);
    F("trap.txt", "[LAZARUS] You opened the box. The cat was me.\n");

    n = 5;
    add_node(l, "6.62.0.50", "superposition", "Superposition core.", USR, 0);
    set_knock(l, "6626 1054 2998");
    set_trip(l, 75);
    F("README.txt", "SUPERPOSITION -- collapse.pin (keypad, two shells).\n");
    FPIN("collapse.pin", "WDBPTzRLSFY=", PUZZLE_ONION, 0, "b64>atb", "1321");
}

/* Level 34 (idx 33) — Lazarus Core (EVENT HORIZON+)
   Every mechanic at once, 8 nodes, 2 attempts. */
static void init_level33(void) {
    Level *l = &levels[33];
    memset(l, 0, sizeof(*l));
    l->id = 33;
    strncpy(l->name,       "Lazarus Core", MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "EVENT HORIZON+", 15);
    strncpy(l->objective,
        "The LAZARUS core. Four fragments, eight nodes, two\n"
        "unlabelled honeypots. Adaptive detection, sweeps every\n"
        "6, a firewalled soul-gate with a keypad, a bruteforce\n"
        "lab, and an ALARMED, WATCHED core that needs override.\n"
        "Two login attempts. The ossuary log knows the way.", 511);
    strncpy(l->warnings, "TIMED 300s | ADAPTIVE | SWEEPS /6 | TRIP 60s | 2 ATTEMPTS", 255);
    strncpy(l->solution_password, "L4ZARUS_N3VER_R1SES", 63);
    strncpy(l->user_password,     "final_witness",       63);
    strncpy(l->hint,
        "HINT: Cred final_witness. grep DECOY lazarus.log: crypt-mirror, ghost-choir.\n"
        "reliquary (WATCHED): relic.oni x3 -> L4ZARUS_\n"
        "resurrection-lab (after reliquary): bruteforce, rebirth.locked -> N3VER_\n"
        "soul-gate: knock 1666 6661 6616, unlock gate.pin 2525 -> R1\n"
        "lazarus-core: override, ls -a, .core_frag -> SES", MAX_HINT - 1);
    l->max_attempts       = 2;
    l->detection_max      = 180;
    l->detection_per_fail = 30;
    l->has_timer          = 1;
    l->timer_seconds      = 300;
    l->hint_cost          = 25;
    l->sweep_interval     = 6;
    l->adaptive_detection = 1;
    l->available_cmds     = ACT4_CMDS | CMD_KNOCK | CMD_UNLOCK
                          | CMD_BRUTEFORCE | CMD_OVERRIDE;
    strncpy(l->bf_node, "resurrection-lab", MAX_NODE_NAME - 1);
    strncpy(l->bf_file, "rebirth.locked",   MAX_FILENAME - 1);
    strncpy(l->ov_node, "lazarus-core",     MAX_NODE_NAME - 1);
    strncpy(l->ov_file, ".core_frag",       MAX_FILENAME - 1);

    int n = 0;
    add_node(l, "13.13.0.1", "catacomb", "Catacomb entry.", PUB, 1);
    F("welcome.txt",
        "[LAZARUS] You followed me all the way down. Good.\n"
        "Witness cred: final_witness\n");
    F("topology.txt",
        "  13.13.0.10 ossuary           (USER, writable logs)\n"
        "  13.13.0.20 reliquary         (USER, WATCHED)\n"
        "  13.13.0.30 crypt-mirror      (USER)\n"
        "  13.13.0.40 resurrection-lab  (USER, after reliquary)\n"
        "  13.13.0.50 ghost-choir       (USER)\n"
        "  13.13.0.60 soul-gate         (USER, FILTERED)\n"
        "  13.13.0.99 lazarus-core      (USER, after soul-gate, ALARMED, WATCHED)\n");

    n = 1;
    add_node(l, "13.13.0.10", "ossuary", "Ossuary log vault.", USR, 0);
    mark_logs(l);
    F("lazarus.log",
        "boot: seed accepted, rebuilding core\n"
        "net: crypt-mirror is a DECOY replica\n"
        "net: ghost-choir is a DECOY replica\n"
        "gate: soul-gate knock 1666 6661 6616\n"
        "gate: PIN = the level number where the Architect fell, typed twice\n"
        "core: silent alarm 60s, sentinel watch active\n");

    n = 2;
    add_node(l, "13.13.0.20", "reliquary", "Reliquary.", USR, 0);
    mark_watched(l);
    FON("relic.oni", "NEYgMzQgNDEgNUEgNDkgNDYgNDggNUY=", "b64>hex>atb");

    n = 3;
    add_node(l, "13.13.0.30", "crypt-mirror", "Crypt mirror.", USR, 0);
    mark_honeypot(l);
    F("trap.txt", "[LAZARUS] A mirror in a crypt. Fitting.\n");

    n = 4;
    add_node(l, "13.13.0.40", "resurrection-lab", "Resurrection lab.", USR, 0);
    route_after(l, "reliquary");
    F("README.txt", "Lab -- rebirth.locked (bruteforce). Requiem cipher.\n");
    FLOCK("rebirth.locked", "E3ZUL_", PUZZLE_VIGENERE, 0, "REQUIEM");

    n = 5;
    add_node(l, "13.13.0.50", "ghost-choir", "Ghost choir.", USR, 0);
    mark_honeypot(l);
    F("trap.txt", "[LAZARUS] Sing with us.\n");

    n = 6;
    add_node(l, "13.13.0.60", "soul-gate", "Soul gate.", USR, 0);
    set_knock(l, "1666 6661 6616");
    F("README.txt", "SOUL GATE -- gate.pin keypad. XOR'd with SOUL.\n");
    FPIN("gate.pin", "01 7E", PUZZLE_XOR, 0, "SOUL", "2525");

    n = 7;
    add_node(l, "13.13.0.99", "lazarus-core", "LAZARUS core.", USR, 0);
    route_after(l, "soul-gate");
    set_trip(l, 60);
    mark_watched(l);
    F("seal.txt", "CORE -- override seals .core_frag. Then ls -a. Then RUN.\n");
    FHLOCK(".core_frag", "HVH", PUZZLE_ATBASH, 0, NULL);
}

/* Level 35 (idx 34) — Zero Point (ZERO POINT, FINAL)
   Everything, tighter: sweeps every 5, 90s trace, 4-shell onion, 2 attempts. */
static void init_level34(void) {
    Level *l = &levels[34];
    memset(l, 0, sizeof(*l));
    l->id = 34;
    strncpy(l->name,       "Zero Point", MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "ZERO POINT",  15);
    strncpy(l->objective,
        "LAZARUS's last packet points home -- to the machine the\n"
        "Architect was first compiled on. Your machine. Every\n"
        "mechanic you have survived is here at once. Sweeps\n"
        "every 5. A 90-second trace at the origin. Two attempts.\n"
        "Find out who the Architect really was.", 511);
    strncpy(l->warnings, "TIMED 360s | ADAPTIVE | SWEEPS /5 | TRIP 90s | 2 ATTEMPTS | FINAL", 255);
    strncpy(l->solution_password, "GH0ST_1S_TH3_ARCH1TECT", 63);
    strncpy(l->user_password,     "GHOST",                  63);
    strncpy(l->hint,
        "HINT: Cred: who are you? (GHOST, see whoami). grep echo origin.log -> decoys 3 + recursion.\n"
        "memory-2 (WATCHED): self.oni x4 -> GH0ST_\n"
        "memory-4 (after memory-2): bruteforce, self.locked -> 1S_\n"
        "origin-gate: knock 1010 0101 1111, unlock core.pin 3434 -> TH3_\n"
        "origin: override, ls -a, .origin_frag x2 -> ARCH1TECT", MAX_HINT - 1);
    l->max_attempts       = 2;
    l->detection_max      = 200;
    l->detection_per_fail = 35;
    l->has_timer          = 1;
    l->timer_seconds      = 360;
    l->hint_cost          = 30;
    l->sweep_interval     = 5;
    l->adaptive_detection = 1;
    l->available_cmds     = ACT4_CMDS | CMD_KNOCK | CMD_UNLOCK
                          | CMD_BRUTEFORCE | CMD_OVERRIDE;
    strncpy(l->bf_node, "memory-4",     MAX_NODE_NAME - 1);
    strncpy(l->bf_file, "self.locked",  MAX_FILENAME - 1);
    strncpy(l->ov_node, "origin",       MAX_NODE_NAME - 1);
    strncpy(l->ov_file, ".origin_frag", MAX_FILENAME - 1);

    int n = 0;
    add_node(l, "0.0.0.0", "null-space", "Nowhere. Home.", PUB, 1);
    F("welcome.txt",
        "[ZERO] Hello again.\n"
        "[ZERO] The login is the name you have been typing all along.\n"
        "[ZERO] whoami, if you need reminding.\n");
    F("topology.txt",
        "  0.0.0.1 memory-1     (USER, writable logs)\n"
        "  0.0.0.2 memory-2     (USER, WATCHED)\n"
        "  0.0.0.3 memory-3     (USER)\n"
        "  0.0.0.4 memory-4     (USER, after memory-2)\n"
        "  0.0.0.5 recursion    (USER)\n"
        "  0.0.0.6 origin-gate  (USER, FILTERED)\n"
        "  0.0.0.7 origin       (USER, after origin-gate, ALARMED, WATCHED)\n");

    n = 1;
    add_node(l, "0.0.0.1", "memory-1", "First memory.", USR, 0);
    mark_logs(l);
    F("origin.log",
        "compile #1: target=architect, author=GHOST\n"
        "mem: memory-3 is an echo, not a memory\n"
        "mem: recursion is an echo, not a memory\n"
        "gate: origin-gate knock 1010 0101 1111\n"
        "gate: PIN = systems you breached before this one, typed twice\n"
        "origin: silent alarm 90s, sentinel cadence 5\n");

    n = 2;
    add_node(l, "0.0.0.2", "memory-2", "Second memory.", USR, 0);
    mark_watched(l);
    F("README.txt", "Four shells. Peel fast -- you are being watched.\n");
    FON("self.oni", "RjUgNzQgODQgMDMgMzUgNDU=", "b64>rev>hex>atb");

    n = 3;
    add_node(l, "0.0.0.3", "memory-3", "Third memory?", USR, 0);
    mark_honeypot(l);
    F("trap.txt", "[ZERO] That never happened.\n");

    n = 4;
    add_node(l, "0.0.0.4", "memory-4", "Fourth memory.", USR, 0);
    route_after(l, "memory-2");
    F("README.txt", "self.locked -- bruteforce. Mirror cipher.\n");
    FLOCK("self.locked", "1E_", PUZZLE_VIGENERE, 0, "MIRROR");

    n = 5;
    add_node(l, "0.0.0.5", "recursion", "Recursion.", USR, 0);
    mark_honeypot(l);
    F("trap.txt", "[ZERO] See: recursion.\n");

    n = 6;
    add_node(l, "0.0.0.6", "origin-gate", "Origin gate.", USR, 0);
    set_knock(l, "1010 0101 1111");
    F("README.txt", "ORIGIN GATE -- core.pin keypad, rail-fenced (3).\n");
    FPIN("core.pin", "TH_3", PUZZLE_RAIL, 3, NULL, "3434");

    n = 7;
    add_node(l, "0.0.0.7", "origin", "Origin.", USR, 0);
    route_after(l, "origin-gate");
    set_trip(l, 90);
    mark_watched(l);
    F("seal.txt", "[ZERO] override. ls -a. Two shells. Then say your name.\n");
    FHLOCK(".origin_frag",
        "31 42 20 31 37 20 31 31 20 30 37 20 36 42 20 31 31 20 31 37 20 30 43 20 30 45",
        PUZZLE_ONION, 0, "hex>xor:ZERO");
}

/* ====================================================================
 * Levels 36–45: ACT V — ERASURE.
 * Five agencies are hunting GHOST. Every record must go, and GHOST
 * with it. New mechanics: manual keys (decrypt <file> <key>), per-host
 * root via su, link-only topology, a rotating sentry and knock windows
 * that re-seal. Generated from act5 spec; every fragment is encoded by
 * the generator and verified by decoding through puzzles.c.
 * ==================================================================== */

#define ACT5_CMDS (ACT4_CMDS | CMD_KNOCK | CMD_UNLOCK | CMD_BRUTEFORCE | CMD_OVERRIDE | CMD_SU)

/* Level 36 (idx 35) — Cold Storage (ABYSS) */
static void init_level35(void) {
    Level *l = &levels[35];
    memset(l, 0, sizeof(*l));
    l->id = 35;
    strncpy(l->name,       "Cold Storage", MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "ABYSS", 15);
    strncpy(l->objective,
        "Operation MIRROR is live: five agencies are hunting\n"
        "the Architect -- you. Every record of GHOST has to go.\n"
        "The national cold archive locks its drawers with keys\n"
        "that are NOT on disk. Read the catalog, work out each\n"
        "key, then: decrypt <file> <key>. Wrong keys cost.", 511);
    strncpy(l->warnings, "TIMED 420s | 4 manual keys | hints cost 15", 255);
    strncpy(l->solution_password, "C0LD_K3YS_N3VER_L13", 63);
    strncpy(l->user_password,     "archivist_9", 63);
    strncpy(l->hint,
        "HINT: Cred archivist_9. grep the catalog log on card-catalog.\n"
        "drawer-a frag1.vig key HALVORSEN -> C0LD_\n"
        "drawer-b frag2.cz shift 14 (a fortnight) -> K3YS_\n"
        "drawer-c frag3.rail rails 5 (basement B5) -> N3VER_\n"
        "microfiche first, then deep-freeze frag4.xor key TSORF -> L13", MAX_HINT - 1);
    l->max_attempts = 3;
    l->detection_max = 120;
    l->detection_per_fail = 25;
    l->has_timer = 1;
    l->timer_seconds = 420;
    l->hint_cost = 15;
    l->available_cmds = ACT5_CMDS;

    int n = 0;
    add_node(l, "10.36.0.1", "vault-lobby", "Archive reception.", PUB, 1);
    add_file_full(l, n, "welcome.txt",
        "[ERASURE] Operation MIRROR is live. Five agencies, one target: you.\n"
        "Burn every record of GHOST, starting with the national cold archive.\n"
        "Archivist credential: archivist_9\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
    add_file_full(l, n, "topology.txt",
        "  10.36.0.10 card-catalog  (USER, writable logs)\n"
        "  10.36.0.21 drawer-a      (USER)\n"
        "  10.36.0.22 drawer-b      (USER)\n"
        "  10.36.0.23 drawer-c      (USER)\n"
        "  10.36.0.30 microfiche    (USER)\n"
        "  10.36.0.99 deep-freeze   (USER, via microfiche)\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
    add_file_full(l, n, "field_manual.txt",
        "MANUAL KEYS\n"
        "  Files marked [KEY] keep no key on disk. You supply it:\n"
        "      decrypt <file> <key>\n"
        "  Caesar shifts and rail counts are numbers. Vigenere and XOR keys\n"
        "  are words. A wrong key still 'decodes' -- into garbage -- and the\n"
        "  failed attempt costs a little detection. Think before you type.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 1;
    add_node(l, "10.36.0.10", "card-catalog", "Catalog server.", USR, 0);
    mark_logs(l);
    add_file_full(l, n, "README.txt",
        "Catalog server. The log is long -- grep it.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
    add_file_full(l, n, "catalog.log",
        "07:58 shift start -- archivist on duty: HALVORSEN\n"
        "08:02 drawer-a sealed (Vigenere). key = surname of the archivist on duty\n"
        "08:09 coffee machine offline\n"
        "08:15 drawer-b sealed (Caesar). shift = days in a fortnight\n"
        "08:22 visitor badge 4471 returned\n"
        "08:31 drawer-c sealed (rail fence). rails = basement level of the vault (B5)\n"
        "08:44 deep-freeze payload sealed (XOR). key = vault codename, spelled backwards\n"
        "09:00 vault codename this quarter: FROST\n"
        "09:12 drawer-c maintenance, no change\n"
        "09:30 deep-freeze only accepts readers who checked the microfiche index\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 2;
    add_node(l, "10.36.0.21", "drawer-a", "Drawer A.", USR, 0);
    add_file_full(l, n, "frag1.vig",
        "J0LO_",
        0, PUZZLE_VIGENERE, 0, "HALVORSEN", 0, NULL);
    last_file(l, n)->manual_key = 1;

    n = 3;
    add_node(l, "10.36.0.22", "drawer-b", "Drawer B.", USR, 0);
    add_file_full(l, n, "frag2.cz",
        "Y3MG_",
        0, PUZZLE_CAESAR, 14, NULL, 0, NULL);
    last_file(l, n)->manual_key = 1;

    n = 4;
    add_node(l, "10.36.0.23", "drawer-c", "Drawer C.", USR, 0);
    add_file_full(l, n, "frag3.rail",
        "N3VE_R",
        0, PUZZLE_RAIL, 5, NULL, 0, NULL);
    last_file(l, n)->manual_key = 1;

    n = 5;
    add_node(l, "10.36.0.30", "microfiche", "Microfiche reader.", USR, 0);
    add_file_full(l, n, "index.txt",
        "MICROFICHE INDEX -- reader logged. deep-freeze will now accept you.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 6;
    add_node(l, "10.36.0.99", "deep-freeze", "Deep-freeze vault.", USR, 0);
    route_after(l, "microfiche");
    add_file_full(l, n, "frag4.xor",
        "18 62 7C",
        0, PUZZLE_XOR, 0, "TSORF", 0, NULL);
    last_file(l, n)->manual_key = 1;
    add_file_full(l, n, "assembly.txt",
        "Archive purge key = frag1 + frag2 + frag3 + frag4.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
}

/* Level 37 (idx 36) — Root of Trust (ABYSS) */
static void init_level36(void) {
    Level *l = &levels[36];
    memset(l, 0, sizeof(*l));
    l->id = 36;
    strncpy(l->name,       "Root of Trust", MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "ABYSS", 15);
    strncpy(l->objective,
        "The coalition PKI issued certificates in GHOST's name.\n"
        "Revoke them from the root down. Files marked [ROOT]\n"
        "need root on THAT host: 'su <password>'. Each root\n"
        "password is hidden on another host -- follow the chain\n"
        "RA -> intermediate -> root CA -> HSM.", 511);
    strncpy(l->warnings, "TIMED 450s | su chain | 1 honeypot | manual key", 255);
    strncpy(l->solution_password, "R00T_0F_TRU5T_BR0KEN", 63);
    strncpy(l->user_password,     "pki_auditor", 63);
    strncpy(l->hint,
        "HINT: Cred pki_auditor. crl-dist is a honeypot.\n"
        "ra-server: decrypt badge.b64 -> su enroll-7731 -> frag1.hex R00T_\n"
        "ocsp-responder: grep rootpw -> intermediate-ca root M1DCHA1N\n"
        "intermediate-ca: frag2.atb 0F_; decrypt anchor.vig SHAONE -> TRUST-ANCH0R\n"
        "root-ca: frag3.rail TRU5T_, hsm.b64 -> HSM-0451; hsm-vault frag4.oni BR0KEN", MAX_HINT - 1);
    l->max_attempts = 3;
    l->detection_max = 130;
    l->detection_per_fail = 25;
    l->has_timer = 1;
    l->timer_seconds = 450;
    l->hint_cost = 15;
    l->available_cmds = ACT5_CMDS;

    int n = 0;
    add_node(l, "10.37.0.1", "ca-gateway", "PKI gateway.", PUB, 1);
    add_file_full(l, n, "welcome.txt",
        "Coalition PKI -- every certificate issued to GHOST must be revoked.\n"
        "Auditor credential: pki_auditor\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
    add_file_full(l, n, "topology.txt",
        "  10.37.0.10 ra-server        (USER, root files)\n"
        "  10.37.0.20 ocsp-responder   (USER, writable logs)\n"
        "  10.37.0.30 intermediate-ca  (USER, root files)\n"
        "  10.37.0.40 root-ca          (USER, via intermediate-ca, root files)\n"
        "  10.37.0.50 crl-dist         (USER)\n"
        "  10.37.0.60 hsm-vault        (USER, via root-ca, root files)\n"
        "  10.37.0.70 timestamp-auth   (USER)\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
    add_file_full(l, n, "field_manual.txt",
        "PER-HOST ROOT\n"
        "  su <password>  -> root on the CURRENT host only. The prompt turns to #.\n"
        "  [ROOT] files can't be read, decrypted or grepped without it.\n"
        "  A failed su is logged (half a failure of detection).\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 1;
    add_node(l, "10.37.0.10", "ra-server", "Registration authority.", USR, 0);
    set_su(l, "enroll-7731");
    add_file_full(l, n, "onboarding.txt",
        "New RA admins: your root password is the enrollment code on your badge.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
    add_file_full(l, n, "badge.b64",
        "RU5ST0xMTUVOVCBDT0RFOiBlbnJvbGwtNzczMQ==",
        0, PUZZLE_BASE64, 0, NULL, 0, NULL);
    add_file_full(l, n, "ra_vault.txt",
        "Intermediate CA root password was captured by the OCSP responder's log.\n"
        "grep it for 'rootpw' -- ignore anything marked REVOKED.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
    last_file(l, n)->needs_root = 1;
    add_file_full(l, n, "frag1.hex",
        "52 30 30 54 5F",
        0, PUZZLE_HEX, 0, NULL, 0, NULL);
    last_file(l, n)->needs_root = 1;

    n = 2;
    add_node(l, "10.37.0.20", "ocsp-responder", "OCSP responder.", USR, 0);
    mark_logs(l);
    add_file_full(l, n, "ocsp.log",
        "status good    serial 0x11\n"
        "rootpw(root-ca)=Gl0b4lTrust  [REVOKED]\n"
        "status good    serial 0x12\n"
        "rootpw(intermediate-ca)=M1DCHA1N\n"
        "status revoked serial 0x13 (subject: GHOST)\n"
        "rootpw(hsm-vault)=see root-ca\n"
        "crl-dist flagged: tampered, do not trust\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 3;
    add_node(l, "10.37.0.30", "intermediate-ca", "Intermediate CA.", USR, 0);
    set_su(l, "M1DCHA1N");
    add_file_full(l, n, "README.txt",
        "Intermediate CA. Root-only material below.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
    add_file_full(l, n, "frag2.atb",
        "0U_",
        0, PUZZLE_ATBASH, 0, NULL, 0, NULL);
    last_file(l, n)->needs_root = 1;
    add_file_full(l, n, "key_note.txt",
        "anchor.vig key: the hash algorithm we deprecated, written in letters --\n"
        "SHA followed by its number spelled out.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
    last_file(l, n)->needs_root = 1;
    add_file_full(l, n, "anchor.vig",
        "jvoh-pe jvoh cekzwceh: LYUGG-EFJH0F",
        0, PUZZLE_VIGENERE, 0, "SHAONE", 0, NULL);
    last_file(l, n)->manual_key = 1;
    last_file(l, n)->needs_root = 1;

    n = 4;
    add_node(l, "10.37.0.40", "root-ca", "Root certificate authority.", USR, 0);
    route_after(l, "intermediate-ca");
    set_su(l, "TRUST-ANCH0R");
    add_file_full(l, n, "frag3.rail",
        "TTR5_U",
        0, PUZZLE_RAIL, 3, NULL, 0, NULL);
    last_file(l, n)->needs_root = 1;
    add_file_full(l, n, "hsm_note.txt",
        "The HSM root PIN is kept in hsm.b64.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
    last_file(l, n)->needs_root = 1;
    add_file_full(l, n, "hsm.b64",
        "aHNtLXZhdWx0IHJvb3QgPSBIU00tMDQ1MQ==",
        0, PUZZLE_BASE64, 0, NULL, 0, NULL);
    last_file(l, n)->needs_root = 1;

    n = 5;
    add_node(l, "10.37.0.50", "crl-dist", "CRL distribution point.", USR, 0);
    mark_honeypot(l);
    add_file_full(l, n, "trap.txt",
        "[MIRROR] Revocation request traced. Hello, GHOST.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 6;
    add_node(l, "10.37.0.60", "hsm-vault", "Hardware security module.", USR, 0);
    route_after(l, "root-ca");
    set_su(l, "HSM-0451");
    add_file_full(l, n, "frag4.oni",
        "TkVLMFJC",
        0, PUZZLE_ONION, 0, "b64>rev", 0, NULL);
    last_file(l, n)->needs_root = 1;
    add_file_full(l, n, "assembly.txt",
        "Revocation key = frag1 + frag2 + frag3 + frag4.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 7;
    add_node(l, "10.37.0.70", "timestamp-auth", "Timestamp authority.", USR, 0);
    add_file_full(l, n, "ts.log",
        "tsa: 1 432 timestamps issued. nothing of interest.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
}

/* Level 38 (idx 37) — Pivot Point (ABYSS+) */
static void init_level37(void) {
    Level *l = &levels[37];
    memset(l, 0, sizeof(*l));
    l->id = 37;
    strncpy(l->name,       "Pivot Point", MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "ABYSS+", 15);
    strncpy(l->objective,
        "A defence contractor network built in layers: DMZ,\n"
        "jumpbox, app and data tiers, backups, core. Hosts only\n"
        "accept sessions from LINKED neighbours -- pivot hop by\n"
        "hop using the link map. The jumpbox is WATCHED (sweep\n"
        "every 8) and every route back passes through it.", 511);
    strncpy(l->warnings, "TIMED 480s | LINKS | SWEEPS /8 | su | knock | 1 honeypot", 255);
    strncpy(l->solution_password, "P1VOT_THR0UGH_TH3_DMZ", 63);
    strncpy(l->user_password,     "red_team_lead", 63);
    strncpy(l->hint,
        "HINT: Cred red_team_lead. mgmt-vlan is a honeypot.\n"
        "edge -> dmz-mail (spool: jumpbox root morris1988) -> dmz-web frag1.atb P1VOT_\n"
        "dmz-web -> jumpbox: su morris1988, frag2.vig key BASTION -> THR0UGH_\n"
        "jumpbox -> app-tier: grep knock -> 179 646 22\n"
        "db-tier frag3.rail rails 3 -> TH3_ ; backup-net -> knock -> core-switch DMZ", MAX_HINT - 1);
    l->max_attempts = 3;
    l->detection_max = 130;
    l->detection_per_fail = 25;
    l->has_timer = 1;
    l->timer_seconds = 480;
    l->hint_cost = 18;
    l->sweep_interval = 8;
    l->available_cmds = ACT5_CMDS;

    int n = 0;
    add_node(l, "10.38.0.1", "edge-router", "Perimeter router.", PUB, 1);
    add_file_full(l, n, "welcome.txt",
        "Contractor network. They keep GHOST's dossier on the core switch.\n"
        "Red team credential: red_team_lead\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
    add_file_full(l, n, "topology.txt",
        "LINK MAP -- you can only connect along a link:\n"
        "  edge-router <-> dmz-web, dmz-mail\n"
        "  dmz-web     <-> dmz-mail, jumpbox\n"
        "  jumpbox     <-> app-tier, db-tier    (WATCHED, sweep every 8)\n"
        "  app-tier    <-> db-tier, mgmt-vlan\n"
        "  db-tier     <-> backup-net           (writable logs)\n"
        "  backup-net  <-> core-switch          (core-switch FILTERED)\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
    add_file_full(l, n, "field_manual.txt",
        "LINKS: 'connect' only works from a host that links to the target.\n"
        "  Wrong hop = NO ROUTE (half a failure). Plan the path first.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 1;
    add_node(l, "10.38.0.10", "dmz-web", "DMZ web server.", USR, 0);
    set_link(l, "edge-router,dmz-mail,jumpbox");
    add_file_full(l, n, "frag1.atb",
        "K1ELG_",
        0, PUZZLE_ATBASH, 0, NULL, 0, NULL);

    n = 2;
    add_node(l, "10.38.0.11", "dmz-mail", "DMZ mail relay.", USR, 0);
    set_link(l, "edge-router,dmz-web");
    add_file_full(l, n, "spool.txt",
        "From: sysadmin\n"
        "To: ops\n"
        "Subject: jumpbox\n"
        "Root on the jumpbox is the name of the first internet worm, lowercase,\n"
        "followed by the year it hit: morris1988\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 3;
    add_node(l, "10.38.0.20", "jumpbox", "Bastion jump host.", USR, 0);
    mark_watched(l);
    set_su(l, "morris1988");
    set_link(l, "dmz-web,app-tier,db-tier");
    add_file_full(l, n, "motd.txt",
        "Bastion. All sessions recorded. Root files need su.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
    add_file_full(l, n, "jump_notes.txt",
        "frag2 key: what a hardened jump host is called (7 letters).\n"
        "db-tier rail count = number of links on this jumpbox.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
    last_file(l, n)->needs_root = 1;
    add_file_full(l, n, "frag2.vig",
        "UHJ0NOV_",
        0, PUZZLE_VIGENERE, 0, "BASTION", 0, NULL);
    last_file(l, n)->manual_key = 1;
    last_file(l, n)->needs_root = 1;

    n = 4;
    add_node(l, "10.38.0.30", "app-tier", "Application tier.", USR, 0);
    set_link(l, "jumpbox,db-tier,mgmt-vlan");
    add_file_full(l, n, "app.log",
        "deploy v4.2 ok\n"
        "core-switch maintenance knock: 179 646 22\n"
        "healthcheck ok\n"
        "mgmt-vlan: unknown device answering ARP. do not touch.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 5;
    add_node(l, "10.38.0.40", "db-tier", "Database tier.", USR, 0);
    mark_logs(l);
    set_link(l, "jumpbox,app-tier,backup-net");
    add_file_full(l, n, "frag3.rail",
        "TH_3",
        0, PUZZLE_RAIL, 3, NULL, 0, NULL);
    last_file(l, n)->manual_key = 1;

    n = 6;
    add_node(l, "10.38.0.50", "mgmt-vlan", "Management VLAN.", USR, 0);
    mark_honeypot(l);
    set_link(l, "app-tier");
    add_file_full(l, n, "trap.txt",
        "[MIRROR] Management plane tripwire. Session fingerprinted.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 7;
    add_node(l, "10.38.0.60", "backup-net", "Backup network.", USR, 0);
    set_link(l, "db-tier,core-switch");
    add_file_full(l, n, "backup.txt",
        "Nightly backups push to core-switch. Knock before you connect.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 8;
    add_node(l, "10.38.0.99", "core-switch", "Core switch.", USR, 0);
    set_knock(l, "179 646 22");
    set_link(l, "backup-net");
    add_file_full(l, n, "frag4.hex",
        "44 4D 5A",
        0, PUZZLE_HEX, 0, NULL, 0, NULL);
    add_file_full(l, n, "assembly.txt",
        "Dossier wipe key = frag1 + frag2 + frag3 + frag4.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
}

/* Level 39 (idx 38) — Carousel (ABYSS+) */
static void init_level38(void) {
    Level *l = &levels[38];
    memset(l, 0, sizeof(*l));
    l->id = 38;
    strncpy(l->name,       "Carousel", MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "ABYSS+", 15);
    strncpy(l->objective,
        "An embassy watches its compound through four cameras\n"
        "on a CAROUSEL: each sweep (every 5 commands) the\n"
        "sentry looks through ONE camera, rotating north, east,\n"
        "south, west. 'status' shows the live camera and the\n"
        "next one. Visit each camera while the sentry looks\n"
        "elsewhere.", 511);
    strncpy(l->warnings, "TIMED 480s | ROTATING SENTRY /5 | links | su | 3 manual keys", 255);
    strncpy(l->solution_password, "CAR0USEL_0F_F0UR_EYES", 63);
    strncpy(l->user_password,     "lens_tech", 63);
    strncpy(l->hint,
        "HINT: Cred lens_tech. cam-spare is a honeypot.\n"
        "ring-road: grep root -> control-room root argus-100\n"
        "control-room: su, cat keys.txt (shift 6, rails 3, key PANOPTES)\n"
        "cam-north oni x2 CAR0USEL_ | cam-east cz 6 0F_ | cam-south rail 3 F0UR_\n"
        "cam-west vig PANOPTES EYES. Check status before each camera.", MAX_HINT - 1);
    l->max_attempts = 3;
    l->detection_max = 140;
    l->detection_per_fail = 25;
    l->has_timer = 1;
    l->timer_seconds = 480;
    l->hint_cost = 18;
    l->sweep_interval = 5;
    l->watch_cycle = 4;
    l->available_cmds = ACT5_CMDS;

    int n = 0;
    add_node(l, "10.39.0.1", "security-desk", "Embassy security desk.", PUB, 1);
    add_file_full(l, n, "welcome.txt",
        "Embassy compound. Technician credential: lens_tech\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
    add_file_full(l, n, "topology.txt",
        "LINKS: every camera and the control room hang off ring-road.\n"
        "  security-desk <-> ring-road\n"
        "  ring-road     <-> cam-north, cam-east, cam-south, cam-west,\n"
        "                    cam-spare, control-room   (writable logs)\n"
        "SENTRY CAROUSEL (one live camera per sweep, in this order):\n"
        "  cam-north -> cam-east -> cam-south -> cam-west -> repeat\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 1;
    add_node(l, "10.39.0.10", "ring-road", "Compound ring network.", USR, 0);
    mark_logs(l);
    set_link(l, "security-desk,cam-north,cam-east,cam-south,cam-west,cam-spare,control-room");
    add_file_full(l, n, "ring.log",
        "carousel started, dwell 5 operator actions per camera\n"
        "control-room root password rotated: argus-100\n"
        "cam-spare offline since Tuesday -- anything answering there is not ours\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 2;
    add_node(l, "10.39.0.21", "cam-north", "North camera.", USR, 0);
    set_link(l, "ring-road");
    set_slot(l, 1);
    add_file_full(l, n, "frag1.oni",
        "WFpJMEZIVk9f",
        0, PUZZLE_ONION, 0, "b64>atb", 0, NULL);

    n = 3;
    add_node(l, "10.39.0.22", "cam-east", "East camera.", USR, 0);
    set_link(l, "ring-road");
    set_slot(l, 2);
    add_file_full(l, n, "frag2.cz",
        "0L_",
        0, PUZZLE_CAESAR, 6, NULL, 0, NULL);
    last_file(l, n)->manual_key = 1;

    n = 4;
    add_node(l, "10.39.0.23", "cam-south", "South camera.", USR, 0);
    set_link(l, "ring-road");
    set_slot(l, 3);
    add_file_full(l, n, "frag3.rail",
        "F_0RU",
        0, PUZZLE_RAIL, 3, NULL, 0, NULL);
    last_file(l, n)->manual_key = 1;

    n = 5;
    add_node(l, "10.39.0.24", "cam-west", "West camera.", USR, 0);
    set_link(l, "ring-road");
    set_slot(l, 4);
    add_file_full(l, n, "frag4.vig",
        "TYRG",
        0, PUZZLE_VIGENERE, 0, "PANOPTES", 0, NULL);
    last_file(l, n)->manual_key = 1;

    n = 6;
    add_node(l, "10.39.0.30", "control-room", "Camera control room.", USR, 0);
    set_su(l, "argus-100");
    set_link(l, "ring-road");
    add_file_full(l, n, "keys.txt",
        "cam-east  Caesar shift: 6\n"
        "cam-south rail count  : 3\n"
        "cam-west  Vigenere key: the hundred-eyed giant's other name -- PANOPTES\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
    last_file(l, n)->needs_root = 1;

    n = 7;
    add_node(l, "10.39.0.40", "cam-spare", "Spare camera.", USR, 0);
    mark_honeypot(l);
    set_link(l, "ring-road");
    add_file_full(l, n, "trap.txt",
        "[MIRROR] The spare camera was watching you.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
}

/* Level 40 (idx 39) — Knock Window (ABYSS++) */
static void init_level39(void) {
    Level *l = &levels[39];
    memset(l, 0, sizeof(*l));
    l->id = 39;
    strncpy(l->name,       "Knock Window", MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "ABYSS++", 15);
    strncpy(l->objective,
        "A naval port hides GHOST's file behind three gates\n"
        "whose firewalls RE-SEAL a few commands after you knock\n"
        "-- connect inside the window or knock again. Gate-2 is\n"
        "WATCHED (sweep every 7). The lighthouse is ALARMED:\n"
        "60s trace from first touch. Plan every move.", 511);
    strncpy(l->warnings, "TIMED 480s | KNOCK WINDOWS | SWEEPS /7 | TRIP 60s | su", 255);
    strncpy(l->solution_password, "W1ND0W_0F_0PP0RTUN1TY", 63);
    strncpy(l->user_password,     "port_warden", 63);
    strncpy(l->hint,
        "HINT: Cred port_warden. smuggler-cove is a honeypot.\n"
        "harbor-log: grep gate -> knocks + windows, grep shift -> 12\n"
        "gate-1 (window 4): frag1.oni W1ND0W_ ; dock-a (via gate-1): frag2.cz 12 -> 0F_\n"
        "gate-2 (window 3, watched): frag3.rail 3 -> 0PP0R, keeper.txt -> beacon-1849\n"
        "lighthouse (window 2, alarmed): su beacon-1849, frag4.xor KEEPER -> TUN1TY", MAX_HINT - 1);
    l->max_attempts = 3;
    l->detection_max = 140;
    l->detection_per_fail = 25;
    l->has_timer = 1;
    l->timer_seconds = 480;
    l->hint_cost = 20;
    l->sweep_interval = 7;
    l->available_cmds = ACT5_CMDS;

    int n = 0;
    add_node(l, "10.40.0.1", "harbor-gate", "Harbour entry.", PUB, 1);
    add_file_full(l, n, "welcome.txt",
        "Naval port. Warden credential: port_warden\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
    add_file_full(l, n, "topology.txt",
        "  10.40.0.10 harbor-log     (USER, writable logs)\n"
        "  10.40.0.20 gate-1         (USER, FILTERED, window)\n"
        "  10.40.0.21 dock-a         (USER, linked to gate-1 only)\n"
        "  10.40.0.30 gate-2         (USER, FILTERED, window, WATCHED)\n"
        "  10.40.0.40 lighthouse     (USER, FILTERED, window, ALARMED)\n"
        "  10.40.0.50 smuggler-cove  (USER)\n"
        "  10.40.0.60 customs        (USER)\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
    add_file_full(l, n, "field_manual.txt",
        "KNOCK WINDOWS: once a knock sequence completes, the firewall stays open\n"
        "for only N commands. Connect inside the window. Late = re-sealed (half\n"
        "a failure) and you knock the whole sequence again. 'status' counts down.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 1;
    add_node(l, "10.40.0.10", "harbor-log", "Harbour master's log.", USR, 0);
    mark_logs(l);
    add_file_full(l, n, "harbor.log",
        "06:00 tide high\n"
        "06:10 gate-1 knock 1111 2222, window 4\n"
        "06:12 gate-2 knock 3141 5926 5358, window 3\n"
        "06:15 lighthouse knock 1849 1849, window 2 (keeper has the root)\n"
        "06:20 dock-a cipher: Caesar, shift = hours between high and low tide x2 = 12\n"
        "06:31 smuggler-cove: unregistered vessel, do not board\n"
        "07:00 tide low\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 2;
    add_node(l, "10.40.0.20", "gate-1", "Gate one.", USR, 0);
    set_knock(l, "1111 2222");
    set_window(l, 4);
    add_file_full(l, n, "frag1.oni",
        "5F 57 30 44 4E 31 57",
        0, PUZZLE_ONION, 0, "hex>rev", 0, NULL);

    n = 3;
    add_node(l, "10.40.0.21", "dock-a", "Dock A.", USR, 0);
    set_link(l, "gate-1");
    add_file_full(l, n, "frag2.cz",
        "0R_",
        0, PUZZLE_CAESAR, 12, NULL, 0, NULL);
    last_file(l, n)->manual_key = 1;

    n = 4;
    add_node(l, "10.40.0.30", "gate-2", "Gate two.", USR, 0);
    mark_watched(l);
    set_knock(l, "3141 5926 5358");
    set_window(l, 3);
    add_file_full(l, n, "frag3.rail",
        "0RP0P",
        0, PUZZLE_RAIL, 3, NULL, 0, NULL);
    last_file(l, n)->manual_key = 1;
    add_file_full(l, n, "keeper.txt",
        "Lighthouse root password: beacon-1849\n"
        "Payload XOR key: KEEPER\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 5;
    add_node(l, "10.40.0.40", "lighthouse", "Lighthouse.", USR, 0);
    set_trip(l, 60);
    set_knock(l, "1849 1849");
    set_window(l, 2);
    set_su(l, "beacon-1849");
    add_file_full(l, n, "frag4.xor",
        "1F 10 0B 61 11 0B",
        0, PUZZLE_XOR, 0, "KEEPER", 0, NULL);
    last_file(l, n)->manual_key = 1;
    last_file(l, n)->needs_root = 1;
    add_file_full(l, n, "assembly.txt",
        "Port wipe key = frag1 + frag2 + frag3 + frag4.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 6;
    add_node(l, "10.40.0.50", "smuggler-cove", "Smuggler's cove.", USR, 0);
    mark_honeypot(l);
    add_file_full(l, n, "trap.txt",
        "[MIRROR] Boarded. Identity captured.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 7;
    add_node(l, "10.40.0.60", "customs", "Customs office.", USR, 0);
    add_file_full(l, n, "manifest.txt",
        "Cargo manifest: nothing for you here.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
}

/* Level 41 (idx 40) — Interpol Mesh (OBLIVION) */
static void init_level40(void) {
    Level *l = &levels[40];
    memset(l, 0, sizeof(*l));
    l->id = 40;
    strncpy(l->name,       "Interpol Mesh", MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "OBLIVION", 15);
    strncpy(l->objective,
        "Interpol's notice mesh holds the red notice on GHOST.\n"
        "Nine hosts, linked. Two mirrors are UNLABELLED\n"
        "honeypots -- the notice log knows which. red-desk is\n"
        "WATCHED (sweep 7). Two su chains, two manual keys, a\n"
        "bruteforce on vault-17 and a knocked void-gate.", 511);
    strncpy(l->warnings, "TIMED 540s | links | SWEEPS /7 | 2 honeypots | bruteforce | knock", 255);
    strncpy(l->solution_password, "1NTERP0L_R3D_N0T1CE_V01D", 63);
    strncpy(l->user_password,     "liaison_nine", 63);
    strncpy(l->hint,
        "HINT: Cred liaison_nine. grep DECOY: eu-mirror, asia-mirror.\n"
        "notice-db grep root -> red-desk root Lyon-1923; red-desk oni x3 -> 1NTERP0L_\n"
        "archive frag2.xor key INTERPOL -> R3D_\n"
        "vault-17 bruteforce -> notice.locked N0T1CE_, custody.txt -> cipher-room root I24-7\n"
        "cipher-room: knock void-gate 1923 247 7; void-gate frag4.cz 23 -> V01D", MAX_HINT - 1);
    l->max_attempts = 3;
    l->detection_max = 160;
    l->detection_per_fail = 25;
    l->has_timer = 1;
    l->timer_seconds = 540;
    l->hint_cost = 20;
    l->sweep_interval = 7;
    l->available_cmds = ACT5_CMDS;
    strncpy(l->bf_node, "vault-17", MAX_NODE_NAME - 1);
    strncpy(l->bf_file, "notice.locked", MAX_FILENAME - 1);

    int n = 0;
    add_node(l, "10.41.0.1", "lyon-hq", "Interpol headquarters.", PUB, 1);
    add_file_full(l, n, "welcome.txt",
        "Notice mesh. Liaison credential: liaison_nine\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
    add_file_full(l, n, "topology.txt",
        "LINK MAP:\n"
        "  lyon-hq     <-> notice-db\n"
        "  notice-db   <-> red-desk, archive        (writable logs)\n"
        "  red-desk    <-> archive, eu-mirror       (WATCHED, sweep 7)\n"
        "  archive     <-> asia-mirror, vault-17\n"
        "  vault-17    <-> cipher-room\n"
        "  cipher-room <-> void-gate                (void-gate FILTERED)\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 1;
    add_node(l, "10.41.0.10", "notice-db", "Notice database.", USR, 0);
    mark_logs(l);
    set_link(l, "lyon-hq,red-desk,archive");
    add_file_full(l, n, "notice.log",
        "sync eu-mirror: DECOY replica planted by MIRROR, ignore\n"
        "sync asia-mirror: DECOY replica planted by MIRROR, ignore\n"
        "red-desk root password: Lyon-1923\n"
        "archive XOR key: the organisation's name in capitals\n"
        "void-gate Caesar shift: the year Interpol was founded, last two digits\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 2;
    add_node(l, "10.41.0.20", "red-desk", "Red notice desk.", USR, 0);
    mark_watched(l);
    set_su(l, "Lyon-1923");
    set_link(l, "notice-db,archive,eu-mirror");
    add_file_full(l, n, "frag1.oni",
        "RjUgQzQgMDMgMDUgMjUgNTQgNDUgRTQgMTM=",
        0, PUZZLE_ONION, 0, "b64>rev>hex", 0, NULL);
    last_file(l, n)->needs_root = 1;

    n = 3;
    add_node(l, "10.41.0.30", "archive", "Notice archive.", USR, 0);
    set_link(l, "notice-db,red-desk,asia-mirror,vault-17");
    add_file_full(l, n, "frag2.xor",
        "1B 7D 10 1A",
        0, PUZZLE_XOR, 0, "INTERPOL", 0, NULL);
    last_file(l, n)->manual_key = 1;

    n = 4;
    add_node(l, "10.41.0.40", "eu-mirror", "EU mirror.", USR, 0);
    mark_honeypot(l);
    set_link(l, "red-desk");
    add_file_full(l, n, "trap.txt",
        "[MIRROR] Wrong reflection, GHOST.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 5;
    add_node(l, "10.41.0.41", "asia-mirror", "Asia mirror.", USR, 0);
    mark_honeypot(l);
    set_link(l, "archive");
    add_file_full(l, n, "trap.txt",
        "[MIRROR] We see you.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 6;
    add_node(l, "10.41.0.50", "vault-17", "Evidence vault 17.", USR, 0);
    set_link(l, "archive,cipher-room");
    add_file_full(l, n, "README.txt",
        "Evidence vault. notice.locked needs bruteforce.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
    add_file_full(l, n, "notice.locked",
        "N_0ETC1",
        0, PUZZLE_RAIL, 4, NULL, 1, NULL);
    add_file_full(l, n, "custody.txt",
        "Chain of custody -- cipher-room root: I24-7\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 7;
    add_node(l, "10.41.0.60", "cipher-room", "Cipher room.", USR, 0);
    set_su(l, "I24-7");
    set_link(l, "vault-17,void-gate");
    add_file_full(l, n, "routing.txt",
        "void-gate knock: 1923 247 7\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
    last_file(l, n)->needs_root = 1;

    n = 8;
    add_node(l, "10.41.0.70", "void-gate", "Void gate.", USR, 0);
    set_knock(l, "1923 247 7");
    set_link(l, "cipher-room");
    add_file_full(l, n, "frag4.cz",
        "S01A",
        0, PUZZLE_CAESAR, 23, NULL, 0, NULL);
    last_file(l, n)->manual_key = 1;
    add_file_full(l, n, "assembly.txt",
        "Notice void key = frag1 + frag2 + frag3 + frag4.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
}

/* Level 42 (idx 41) — Five Eyes (OBLIVION) */
static void init_level41(void) {
    Level *l = &levels[41];
    memset(l, 0, sizeof(*l));
    l->id = 41;
    strncpy(l->name,       "Five Eyes", MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "OBLIVION", 15);
    strncpy(l->objective,
        "The five-nation SIGINT alliance shares one core. Its\n"
        "five stations sit on a rotating sentry (sweep every 5,\n"
        "one live station per sweep). The core is FILTERED with\n"
        "a 3-command window, ALARMED (90s) and override-sealed.\n"
        "Leitrim's intercept log ties it all together.", 511);
    strncpy(l->warnings, "TIMED 540s | ROTATING SENTRY x5 | knock window | TRIP 90s | override", 255);
    strncpy(l->solution_password, "F1VE_EY3S_W1DE_SHUT", 63);
    strncpy(l->user_password,     "echelon_tap", 63);
    strncpy(l->hint,
        "HINT: Cred echelon_tap. ghost-station is a honeypot.\n"
        "leitrim: grep -> key ECHELON, waihopai root kiwi-0x5, rails 3, knock 1946 1955 2001\n"
        "pine-gap vig ECHELON F1VE_ | menwith oni x2 EY3S_ | waihopai su, rail 3 W1DE_\n"
        "ukusa-core (window 3, 90s trace): override, decrypt .final -> SHUT\n"
        "Watch status: never be on the live station at a sweep.", MAX_HINT - 1);
    l->max_attempts = 3;
    l->detection_max = 170;
    l->detection_per_fail = 30;
    l->has_timer = 1;
    l->timer_seconds = 540;
    l->hint_cost = 22;
    l->sweep_interval = 5;
    l->watch_cycle = 5;
    l->available_cmds = ACT5_CMDS;
    strncpy(l->ov_node, "ukusa-core", MAX_NODE_NAME - 1);
    strncpy(l->ov_file, ".final", MAX_FILENAME - 1);

    int n = 0;
    add_node(l, "10.42.0.1", "echelon-tap", "Fibre tap.", PUB, 1);
    add_file_full(l, n, "welcome.txt",
        "Undersea fibre tap. Credential: echelon_tap\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
    add_file_full(l, n, "topology.txt",
        "  10.42.0.11 pine-gap       (USER, rotation 1)\n"
        "  10.42.0.12 menwith        (USER, rotation 2)\n"
        "  10.42.0.13 waihopai       (USER, rotation 3, root files)\n"
        "  10.42.0.14 leitrim        (USER, rotation 4, writable logs)\n"
        "  10.42.0.15 yakima         (USER, rotation 5)\n"
        "  10.42.0.66 ghost-station  (USER)\n"
        "  10.42.0.99 ukusa-core     (USER, FILTERED, ALARMED)\n"
        "SENTRY: one live station per sweep, in rotation order 1 -> 5.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 1;
    add_node(l, "10.42.0.11", "pine-gap", "Pine Gap.", USR, 0);
    set_slot(l, 1);
    add_file_full(l, n, "frag1.vig",
        "J1XL_",
        0, PUZZLE_VIGENERE, 0, "ECHELON", 0, NULL);
    last_file(l, n)->manual_key = 1;

    n = 2;
    add_node(l, "10.42.0.12", "menwith", "Menwith Hill.", USR, 0);
    set_slot(l, 2);
    add_file_full(l, n, "frag2.oni",
        "VkIzSF8=",
        0, PUZZLE_ONION, 0, "b64>atb", 0, NULL);

    n = 3;
    add_node(l, "10.42.0.13", "waihopai", "Waihopai.", USR, 0);
    set_su(l, "kiwi-0x5");
    set_slot(l, 3);
    add_file_full(l, n, "frag3.rail",
        "W_1ED",
        0, PUZZLE_RAIL, 3, NULL, 0, NULL);
    last_file(l, n)->manual_key = 1;
    last_file(l, n)->needs_root = 1;

    n = 4;
    add_node(l, "10.42.0.14", "leitrim", "Leitrim.", USR, 0);
    mark_logs(l);
    set_slot(l, 4);
    add_file_full(l, n, "sigint.log",
        "intercept 0x01: pine-gap Vigenere key ECHELON\n"
        "intercept 0x02: waihopai root password kiwi-0x5\n"
        "intercept 0x03: waihopai rail count 3\n"
        "intercept 0x04: ukusa-core knock 1946 1955 2001, window 3\n"
        "intercept 0x05: ghost-station is a MIRROR lure\n"
        "intercept 0x06: ukusa-core seal needs override; core alarm 90s\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 5;
    add_node(l, "10.42.0.15", "yakima", "Yakima.", USR, 0);
    set_slot(l, 5);
    add_file_full(l, n, "status.txt",
        "Station decommissioned. Dish still turns.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 6;
    add_node(l, "10.42.0.66", "ghost-station", "Unlisted station.", USR, 0);
    mark_honeypot(l);
    add_file_full(l, n, "trap.txt",
        "[MIRROR] There is no sixth eye. Except ours.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 7;
    add_node(l, "10.42.0.99", "ukusa-core", "Alliance core.", USR, 0);
    set_trip(l, 90);
    set_knock(l, "1946 1955 2001");
    set_window(l, 3);
    add_file_full(l, n, "seal.txt",
        "Core sealed. override, then decrypt .final.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
    add_file_full(l, n, ".final",
        "HSFG",
        1, PUZZLE_ATBASH, 0, NULL, 1, NULL);
}

/* Level 43 (idx 42) — Black Ledger (OBLIVION+) */
static void init_level42(void) {
    Level *l = &levels[42];
    memset(l, 0, sizeof(*l));
    l->id = 42;
    strncpy(l->name,       "Black Ledger", MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "OBLIVION+", 15);
    strncpy(l->objective,
        "The bank that launders MIRROR's budget keeps a black\n"
        "ledger. Tellers rotate the sentry (sweep 6), the vault\n"
        "corridor is always WATCHED, the system LEARNS your\n"
        "patterns, and two shell companies are traps.\n"
        "Bruteforce the clearing house, override the vault.\n"
        "600s.", 511);
    strncpy(l->warnings, "TIMED 600s | ADAPTIVE | ROTATING /6 | keypad | su | bf + override", 255);
    strncpy(l->solution_password, "BL4CK_L3DG3R_B4LANC3D_Z3RO", 63);
    strncpy(l->user_password,     "ledger_clerk", 63);
    strncpy(l->hint,
        "HINT: Cred ledger_clerk. audit-trail grep: DECOY, root, PIN, key, knock.\n"
        "teller-1 vig SWIFT BL4CK_ | teller-2 unlock ledger.pin 4096 -> L3DG3R_\n"
        "back-office su debit-credit (routing.txt) | clearing bruteforce oni x3 B4LANC3D_\n"
        "knock black-vault 1694 1971 2008 (window 3, alarmed 75s), override\n"
        "decrypt .zero 13 -> Z3RO. Corridor is always watched: pass straight through.", MAX_HINT - 1);
    l->max_attempts = 3;
    l->detection_max = 200;
    l->detection_per_fail = 30;
    l->has_timer = 1;
    l->timer_seconds = 600;
    l->hint_cost = 25;
    l->sweep_interval = 6;
    l->watch_cycle = 2;
    l->adaptive_detection = 1;
    l->available_cmds = ACT5_CMDS;
    strncpy(l->bf_node, "clearing", MAX_NODE_NAME - 1);
    strncpy(l->bf_file, "settle.locked", MAX_FILENAME - 1);
    strncpy(l->ov_node, "black-vault", MAX_NODE_NAME - 1);
    strncpy(l->ov_file, ".zero", MAX_FILENAME - 1);

    int n = 0;
    add_node(l, "10.43.0.1", "front-office", "Bank front office.", PUB, 1);
    add_file_full(l, n, "welcome.txt",
        "Private bank. Clerk credential: ledger_clerk\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
    add_file_full(l, n, "topology.txt",
        "LINK MAP:\n"
        "  front-office <-> teller-1, teller-2\n"
        "  teller-1/2   <-> each other, back-office   (tellers rotate the sentry)\n"
        "  back-office  <-> audit-trail, shell-co-a, shell-co-b, clearing\n"
        "  clearing     <-> vault-corridor            (corridor ALWAYS watched)\n"
        "  vault-corridor <-> black-vault             (FILTERED, ALARMED)\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 1;
    add_node(l, "10.43.0.11", "teller-1", "Teller one.", USR, 0);
    set_link(l, "front-office,teller-2,back-office");
    set_slot(l, 1);
    add_file_full(l, n, "frag1.vig",
        "TH4KP_",
        0, PUZZLE_VIGENERE, 0, "SWIFT", 0, NULL);
    last_file(l, n)->manual_key = 1;

    n = 2;
    add_node(l, "10.43.0.12", "teller-2", "Teller two.", USR, 0);
    set_link(l, "front-office,teller-1,back-office");
    set_slot(l, 2);
    add_file_full(l, n, "ledger.pin",
        "4C 33 44 47 33 52 5F",
        0, PUZZLE_HEX, 0, NULL, 1, "4096");

    n = 3;
    add_node(l, "10.43.0.20", "back-office", "Back office.", USR, 0);
    set_su(l, "debit-credit");
    set_link(l, "teller-1,teller-2,audit-trail,shell-co-a,shell-co-b,clearing");
    add_file_full(l, n, "routing.txt",
        "black-vault knock: 1694 1971 2008 (window 3)\n"
        ".zero shift: half the alphabet\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
    last_file(l, n)->needs_root = 1;

    n = 4;
    add_node(l, "10.43.0.30", "audit-trail", "Audit trail.", USR, 0);
    mark_logs(l);
    set_link(l, "back-office");
    add_file_full(l, n, "audit.log",
        "aml: shell-co-a is a DECOY front, flagged by MIRROR\n"
        "aml: shell-co-b is a DECOY front, flagged by MIRROR\n"
        "ops: back-office root rotated to debit-credit\n"
        "ops: teller-2 keypad PIN = 2 to the power 12\n"
        "ops: teller-1 Vigenere key = the interbank messaging network, SWIFT\n"
        "ops: black-vault knock lives in back-office routing.txt\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 5;
    add_node(l, "10.43.0.40", "shell-co-a", "Shell company A.", USR, 0);
    mark_honeypot(l);
    set_link(l, "back-office");
    add_file_full(l, n, "trap.txt",
        "[MIRROR] Follow the money. We did.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 6;
    add_node(l, "10.43.0.41", "shell-co-b", "Shell company B.", USR, 0);
    mark_honeypot(l);
    set_link(l, "back-office");
    add_file_full(l, n, "trap.txt",
        "[MIRROR] Nice try.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 7;
    add_node(l, "10.43.0.50", "clearing", "Clearing house.", USR, 0);
    set_link(l, "back-office,vault-corridor");
    add_file_full(l, n, "README.txt",
        "settle.locked needs bruteforce.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
    add_file_full(l, n, "settle.locked",
        "RjUgNDQgMzMgMzQgRTQgMTQgQzQgNDMgMjQ=",
        0, PUZZLE_ONION, 0, "b64>rev>hex", 1, NULL);

    n = 8;
    add_node(l, "10.43.0.60", "vault-corridor", "Vault corridor.", USR, 0);
    mark_watched(l);
    set_link(l, "clearing,black-vault");
    add_file_full(l, n, "camera.txt",
        "You are on camera. Keep walking.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 9;
    add_node(l, "10.43.0.99", "black-vault", "The black vault.", USR, 0);
    set_trip(l, 75);
    set_knock(l, "1694 1971 2008");
    set_window(l, 3);
    set_link(l, "vault-corridor");
    add_file_full(l, n, "seal.txt",
        "Vault sealed. override, then: decrypt .zero <shift>\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
    add_file_full(l, n, ".zero",
        "M3EB",
        1, PUZZLE_CAESAR, 13, NULL, 1, NULL);
    last_file(l, n)->manual_key = 1;
}

/* Level 44 (idx 43) — Mirror Protocol (NULL) */
static void init_level43(void) {
    Level *l = &levels[43];
    memset(l, 0, sizeof(*l));
    l->id = 43;
    strncpy(l->name,       "Mirror Protocol", MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "NULL", 15);
    strncpy(l->objective,
        "Operation MIRROR's own command net. Three dossiers on\n"
        "you rotate under the sentry (sweep 5); the switchboard\n"
        "is always WATCHED. Two reflections are traps. You need\n"
        "su twice, three keys, a keypad, a bruteforce, a knock\n"
        "window and an override -- with only TWO logins.", 511);
    strncpy(l->warnings, "TIMED 600s | ADAPTIVE | ROTATING /5 | TRIP 90s | 2 ATTEMPTS", 255);
    strncpy(l->solution_password, "N0_M1RR0R_N0_GH0ST_N0_TRAC3", 63);
    strncpy(l->user_password,     "mirror_handler", 63);
    strncpy(l->hint,
        "HINT: Cred mirror_handler. wiretap grep: DECOY, root, key, PIN, knock.\n"
        "dossier-a xor MI6 -> N0_ | dossier-b oni x3 -> M1RR0R_\n"
        "dossier-c unlock wanted.pin 1984, rail 4 -> N0_GH0ST_\n"
        "switchboard su sw1tchb0ard; signals bruteforce -> null-room root segfault-11\n"
        "knock null-room 0 0 7 (window 3), override, su, decrypt .trace LOOKINGGLASS", MAX_HINT - 1);
    l->max_attempts = 2;
    l->detection_max = 220;
    l->detection_per_fail = 35;
    l->has_timer = 1;
    l->timer_seconds = 600;
    l->hint_cost = 30;
    l->sweep_interval = 5;
    l->watch_cycle = 3;
    l->adaptive_detection = 1;
    l->available_cmds = ACT5_CMDS;
    strncpy(l->bf_node, "signals", MAX_NODE_NAME - 1);
    strncpy(l->bf_file, "sig.locked", MAX_FILENAME - 1);
    strncpy(l->ov_node, "null-room", MAX_NODE_NAME - 1);
    strncpy(l->ov_file, ".trace", MAX_FILENAME - 1);

    int n = 0;
    add_node(l, "10.44.0.1", "operation-mirror", "MIRROR operations floor.", PUB, 1);
    add_file_full(l, n, "welcome.txt",
        "[MIRROR] Handler console. Credential: mirror_handler\n"
        "Three dossiers on GHOST. Burn all of them.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
    add_file_full(l, n, "topology.txt",
        "LINK MAP:\n"
        "  operation-mirror <-> dossier-a, dossier-b, dossier-c\n"
        "  dossier-a/b/c    <-> each other, switchboard   (dossiers rotate the sentry)\n"
        "  switchboard      <-> wiretap, reflection-1, reflection-2, signals  (ALWAYS watched)\n"
        "  signals          <-> null-room                 (FILTERED, ALARMED)\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 1;
    add_node(l, "10.44.0.11", "dossier-a", "Dossier A.", USR, 0);
    set_link(l, "operation-mirror,dossier-b,dossier-c,switchboard");
    set_slot(l, 1);
    add_file_full(l, n, "frag1.xor",
        "03 79 69",
        0, PUZZLE_XOR, 0, "MI6", 0, NULL);
    last_file(l, n)->manual_key = 1;

    n = 2;
    add_node(l, "10.44.0.12", "dossier-b", "Dossier B.", USR, 0);
    set_link(l, "operation-mirror,dossier-a,dossier-c,switchboard");
    set_slot(l, 2);
    add_file_full(l, n, "frag2.oni",
        "NEUgMzEgNDkgNDkgMzAgNDkgNUY=",
        0, PUZZLE_ONION, 0, "b64>hex>atb", 0, NULL);

    n = 3;
    add_node(l, "10.44.0.13", "dossier-c", "Dossier C.", USR, 0);
    set_link(l, "operation-mirror,dossier-a,dossier-b,switchboard");
    set_slot(l, 3);
    add_file_full(l, n, "wanted.pin",
        "NS00T_H_G",
        0, PUZZLE_RAIL, 4, NULL, 1, "1984");
    last_file(l, n)->manual_key = 1;

    n = 4;
    add_node(l, "10.44.0.20", "switchboard", "Switchboard.", USR, 0);
    mark_watched(l);
    set_su(l, "sw1tchb0ard");
    set_link(l, "dossier-a,dossier-b,dossier-c,wiretap,reflection-1,reflection-2,signals");
    add_file_full(l, n, "routing.txt",
        "null-room knock: 0 0 7 (window 3)\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
    last_file(l, n)->needs_root = 1;

    n = 5;
    add_node(l, "10.44.0.30", "wiretap", "Wiretap recorder.", USR, 0);
    mark_logs(l);
    set_link(l, "switchboard");
    add_file_full(l, n, "tap.log",
        "tap: reflection-1 is a DECOY\n"
        "tap: reflection-2 is a DECOY\n"
        "tap: switchboard root = sw1tchb0ard\n"
        "tap: dossier-a XOR key = the British foreign service, three characters\n"
        "tap: dossier-c keypad = Orwell's year; rail count = 4\n"
        "tap: null-room knock is in switchboard routing.txt (root)\n"
        "tap: .trace key = what Alice went through, one word, no spaces\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 6;
    add_node(l, "10.44.0.41", "reflection-1", "Reflection one.", USR, 0);
    mark_honeypot(l);
    set_link(l, "switchboard");
    add_file_full(l, n, "trap.txt",
        "[MIRROR] Look closer.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 7;
    add_node(l, "10.44.0.42", "reflection-2", "Reflection two.", USR, 0);
    mark_honeypot(l);
    set_link(l, "switchboard");
    add_file_full(l, n, "trap.txt",
        "[MIRROR] Closer.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 8;
    add_node(l, "10.44.0.50", "signals", "Signals room.", USR, 0);
    set_link(l, "switchboard,null-room");
    add_file_full(l, n, "README.txt",
        "sig.locked needs bruteforce.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
    add_file_full(l, n, "sig.locked",
        "null-room root password: segfault-11\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 1, NULL);

    n = 9;
    add_node(l, "10.44.0.99", "null-room", "The null room.", USR, 0);
    set_trip(l, 90);
    set_knock(l, "0 0 7");
    set_window(l, 3);
    set_su(l, "segfault-11");
    set_link(l, "signals");
    add_file_full(l, n, "seal.txt",
        "override opens .trace; reading it needs root here.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
    add_file_full(l, n, ".trace",
        "Y0_HFKK3",
        1, PUZZLE_VIGENERE, 0, "LOOKINGGLASS", 1, NULL);
    last_file(l, n)->manual_key = 1;
    last_file(l, n)->needs_root = 1;
}

/* Level 45 (idx 44) — Null Pointer (NULL POINTER) */
static void init_level44(void) {
    Level *l = &levels[44];
    memset(l, 0, sizeof(*l));
    l->id = 44;
    strncpy(l->name,       "Null Pointer", MAX_LEVEL_NAME - 1);
    strncpy(l->difficulty, "NULL POINTER", 15);
    strncpy(l->objective,
        "The last copy of GHOST lives in one process. Free it.\n"
        "Log in as what you were before you were GHOST. Three\n"
        "registers rotate the sentry (sweep 4); the kernel is\n"
        "always WATCHED; three dangling pointers are traps. The\n"
        "null page: knock window 2, 120s trace. Two attempts.", 511);
    strncpy(l->warnings, "TIMED 720s | ADAPTIVE | ROTATING /4 | TRIP 120s | 2 ATTEMPTS | FINAL", 255);
    strncpy(l->solution_password, "FR33_GH0ST_SET_T0_NULL", 63);
    strncpy(l->user_password,     "architect", 63);
    strncpy(l->hint,
        "HINT: Cred: architect. stack grep: DECOY, root, key, PIN, knock.\n"
        "register-a xor MALLOC FR33_ | register-b oni x4 GH0ST_ | register-c pin 0451, rail 3 SET_\n"
        "kernel su ring0, frag4.cz 8 -> T0_ | syscall bruteforce -> null root segv-0xb\n"
        "knock null 0 0 0 0 (window 2), connect, override, su segv-0xb,\n"
        "decrypt .eof DEREFERENCE -> NULL. combine 1 2 3 4 5.", MAX_HINT - 1);
    l->max_attempts = 2;
    l->detection_max = 230;
    l->detection_per_fail = 35;
    l->has_timer = 1;
    l->timer_seconds = 720;
    l->hint_cost = 35;
    l->sweep_interval = 4;
    l->watch_cycle = 3;
    l->adaptive_detection = 1;
    l->available_cmds = ACT5_CMDS;
    strncpy(l->bf_node, "syscall", MAX_NODE_NAME - 1);
    strncpy(l->bf_file, "syscall.locked", MAX_FILENAME - 1);
    strncpy(l->ov_node, "null", MAX_NODE_NAME - 1);
    strncpy(l->ov_file, ".eof", MAX_FILENAME - 1);

    int n = 0;
    add_node(l, "0.0.0.1", "heap", "The heap.", PUB, 1);
    add_file_full(l, n, "welcome.txt",
        "[NULL] One process left. One pointer to you.\n"
        "[NULL] Log in as the name you had before GHOST.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
    add_file_full(l, n, "topology.txt",
        "LINK MAP:\n"
        "  heap        <-> stack\n"
        "  stack       <-> register-a, register-b, register-c, kernel  (writable logs)\n"
        "  register-a  <-> register-b       register-b <-> register-c\n"
        "  kernel      <-> syscall, dangling-1, dangling-2, dangling-3  (ALWAYS watched)\n"
        "  syscall     <-> null             (null: FILTERED, ALARMED)\n"
        "SENTRY: registers a -> b -> c rotate, one per sweep (every 4 commands).\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 1;
    add_node(l, "0.0.0.2", "stack", "The stack.", USR, 0);
    mark_logs(l);
    set_link(l, "heap,register-a,register-b,register-c,kernel");
    add_file_full(l, n, "stack.log",
        "frame 0: dangling-1 -> freed memory, DECOY\n"
        "frame 1: dangling-2 -> freed memory, DECOY\n"
        "frame 2: dangling-3 -> freed memory, DECOY\n"
        "frame 3: kernel root = ring0\n"
        "frame 4: register-a XOR key = the allocator you call for memory, capitals\n"
        "frame 5: register-c keypad = the code everyone tries first in a game, 0451\n"
        "frame 6: register-c rails = 3; kernel shift = bytes in a 64-bit pointer\n"
        "frame 7: null knock = four zeros, window 2\n"
        "frame 8: .eof key = what you do to a pointer to read it\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 2;
    add_node(l, "0.0.0.11", "register-a", "Register A.", USR, 0);
    set_link(l, "stack,register-b");
    set_slot(l, 1);
    add_file_full(l, n, "frag1.xor",
        "0B 13 7F 7F 10",
        0, PUZZLE_XOR, 0, "MALLOC", 0, NULL);
    last_file(l, n)->manual_key = 1;

    n = 3;
    add_node(l, "0.0.0.12", "register-b", "Register B.", USR, 0);
    set_link(l, "stack,register-a,register-c");
    set_slot(l, 2);
    add_file_full(l, n, "frag2.oni",
        "RjUgNzQgODQgMDMgMzUgNDU=",
        0, PUZZLE_ONION, 0, "b64>rev>hex>atb", 0, NULL);

    n = 4;
    add_node(l, "0.0.0.13", "register-c", "Register C.", USR, 0);
    set_link(l, "stack,register-b");
    set_slot(l, 3);
    add_file_full(l, n, "set.pin",
        "SE_T",
        0, PUZZLE_RAIL, 3, NULL, 1, "0451");
    last_file(l, n)->manual_key = 1;

    n = 5;
    add_node(l, "0.0.0.20", "kernel", "Kernel space.", USR, 0);
    mark_watched(l);
    set_su(l, "ring0");
    set_link(l, "stack,syscall,dangling-1,dangling-2,dangling-3");
    add_file_full(l, n, "frag4.cz",
        "B0_",
        0, PUZZLE_CAESAR, 8, NULL, 0, NULL);
    last_file(l, n)->manual_key = 1;
    last_file(l, n)->needs_root = 1;

    n = 6;
    add_node(l, "0.0.0.41", "dangling-1", "Dangling pointer.", USR, 0);
    mark_honeypot(l);
    set_link(l, "kernel");
    add_file_full(l, n, "trap.txt",
        "[NULL] Use after free. That was you.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 7;
    add_node(l, "0.0.0.42", "dangling-2", "Dangling pointer.", USR, 0);
    mark_honeypot(l);
    set_link(l, "kernel");
    add_file_full(l, n, "trap.txt",
        "[NULL] Use after free. That was you.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 8;
    add_node(l, "0.0.0.43", "dangling-3", "Dangling pointer.", USR, 0);
    mark_honeypot(l);
    set_link(l, "kernel");
    add_file_full(l, n, "trap.txt",
        "[NULL] Use after free. That was you.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);

    n = 9;
    add_node(l, "0.0.0.30", "syscall", "Syscall gate.", USR, 0);
    set_link(l, "kernel,null");
    add_file_full(l, n, "README.txt",
        "syscall.locked needs bruteforce.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
    add_file_full(l, n, "syscall.locked",
        "null page root password: segv-0xb\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 1, NULL);

    n = 10;
    add_node(l, "0.0.0.0", "null", "Address zero.", USR, 0);
    set_trip(l, 120);
    set_knock(l, "0 0 0 0");
    set_window(l, 2);
    set_su(l, "segv-0xb");
    set_link(l, "syscall");
    add_file_full(l, n, "seal.txt",
        "[NULL] override. su. decrypt .eof <key>. Then let go.\n"
        "",
        0, PUZZLE_NONE, 0, NULL, 0, NULL);
    add_file_full(l, n, ".eof",
        "QYCP",
        1, PUZZLE_VIGENERE, 0, "DEREFERENCE", 1, NULL);
    last_file(l, n)->manual_key = 1;
    last_file(l, n)->needs_root = 1;
}

/* Wires bruteforce/override targets for the legacy levels (1-25) that used
   to be hard-coded in commands.c. */
static void wire_legacy_targets(void) {
    struct { int idx; const char *bfn, *bff, *ovn, *ovf; } t[] = {
        { 4,  "vault-entry",    "vault_access.txt",    NULL, NULL },
        { 7,  NULL, NULL,                              "neural-net",     ".genesis_key" },
        { 12, "vendor-hub",     "locked_comms.enc",    NULL, NULL },
        { 13, "quantum-relay",  "locked_manifest.txt", "quantum-core",   ".classified_key" },
        { 14, "fragment-beta",  "day.enc",             "omega-core",     ".deactivation_key" },
        { 20, "staging",        "stake.locked",        "payload-vault",  ".winner_frag" },
        { 23, "enclave-b",      "frag_b.locked",       "phantom-c2",     ".frag_c" },
        { 24, "shard-gimel",    "mirror.locked",       "architect-core", ".final_frag" },
    };
    for (size_t i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
        Level *l = &levels[t[i].idx];
        if (t[i].bfn) {
            strncpy(l->bf_node, t[i].bfn, MAX_NODE_NAME - 1);
            strncpy(l->bf_file, t[i].bff, MAX_FILENAME - 1);
        }
        if (t[i].ovn) {
            strncpy(l->ov_node, t[i].ovn, MAX_NODE_NAME - 1);
            strncpy(l->ov_file, t[i].ovf, MAX_FILENAME - 1);
        }
    }
}

/* Initialises all 45 levels in order. Called once at program startup before
   the game loop begins. All Level structs are populated into the static array
   and remain unchanged for the duration of the session. */
void init_levels(void) {
    init_level0();
    init_level1();
    init_level2();
    init_level3();
    init_level4();
    init_level5();
    init_level6();
    init_level7();
    init_level8();
    init_level9();
    init_level10();
    init_level11();
    init_level12();
    init_level13();
    init_level14();
    init_level15();
    init_level16();
    init_level17();
    init_level18();
    init_level19();
    init_level20();
    init_level21();
    init_level22();
    init_level23();
    init_level24();
    init_level25();
    init_level26();
    init_level27();
    init_level28();
    init_level29();
    init_level30();
    init_level31();
    init_level32();
    init_level33();
    init_level34();
    init_level35();
    init_level36();
    init_level37();
    init_level38();
    init_level39();
    init_level40();
    init_level41();
    init_level42();
    init_level43();
    init_level44();
    wire_legacy_targets();
}

/* Returns a pointer to the Level with the given id, or NULL if id is out of
   range. All callers that iterate levels use TOTAL_LEVELS as the bound, so
   NULL should never be returned in normal play — the check is a safety net. */
Level *get_level(int id) {
    if (id < 0 || id >= TOTAL_LEVELS) return NULL;
    return &levels[id];
}
