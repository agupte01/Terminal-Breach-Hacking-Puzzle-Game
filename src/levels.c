/*
 * levels.c — Level definitions for all 16 stages of Terminal Breach.
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
    l->nodes[i].min_perm   = min_perm;
    l->nodes[i].is_entry   = is_entry;
    l->nodes[i].file_count = 0;
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
    n->files[i].min_perm    = min_perm;
    n->files[i].hidden      = hidden;
    n->files[i].encrypted   = encrypted;
    n->files[i].puzzle_type = puzzle_type;
    n->files[i].cipher_shift = cipher_shift;
    n->files[i].locked      = locked;
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
    strncpy(l->name,     "AI Core System [FINAL]",           MAX_LEVEL_NAME - 1);
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

/* Initialises all 16 levels in order. Called once at program startup before
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
}

/* Returns a pointer to the Level with the given id, or NULL if id is out of
   range. All callers that iterate levels use TOTAL_LEVELS as the bound, so
   NULL should never be returned in normal play — the check is a safety net. */
Level *get_level(int id) {
    if (id < 0 || id >= TOTAL_LEVELS) return NULL;
    return &levels[id];
}
