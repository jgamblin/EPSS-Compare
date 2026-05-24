#!/usr/bin/env python3
"""
EPSS V4 vs V5 Beta comparison data pipeline.

Downloads EPSS scores for a given date, enriches with CVE metadata from
CVEProject/cvelistV5, and writes pre-computed JSON summaries for the
GitHub Pages report.

Usage:
    python build.py --date 2026-05-22 --cve-dir ~/Data/cvelistV5
    python build.py --date 2026-05-22 --cve-dir ./cvelistV5 --no-download
"""

import argparse
import gzip
import io
import json
import math
import os
import re
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import orjson
import pandas as pd
import requests
from tqdm import tqdm

EPSS_V4_URL = "https://raw.githubusercontent.com/empiricalsec/epss_scores/main/{year}/epss_scores-{date}.csv.gz"
EPSS_V5_URL = "https://raw.githubusercontent.com/empiricalsec/epss_scores/main/beta_scores/epssv5_beta-{date}.csv.gz"

# Common CWE names (top ~100); others labeled with ID only
CWE_NAMES = {
    "CWE-1": "Location",
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-59": "Symlink Following",
    "CWE-77": "Command Injection",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting",
    "CWE-89": "SQL Injection",
    "CWE-90": "LDAP Injection",
    "CWE-94": "Code Injection",
    "CWE-119": "Buffer Errors",
    "CWE-120": "Buffer Copy w/o Size Check",
    "CWE-121": "Stack-based Buffer Overflow",
    "CWE-122": "Heap-based Buffer Overflow",
    "CWE-125": "Out-of-bounds Read",
    "CWE-126": "Buffer Over-read",
    "CWE-129": "Improper Array Index Validation",
    "CWE-130": "Improper Handling of Length Parameter",
    "CWE-131": "Incorrect Calculation of Buffer Size",
    "CWE-134": "Uncontrolled Format String",
    "CWE-170": "Improper Null Termination",
    "CWE-189": "Numeric Errors",
    "CWE-190": "Integer Overflow",
    "CWE-191": "Integer Underflow",
    "CWE-193": "Off-by-one Error",
    "CWE-200": "Information Exposure",
    "CWE-201": "Information Exposure Through Sent Data",
    "CWE-203": "Observable Discrepancy",
    "CWE-209": "Error Message Info Exposure",
    "CWE-210": "Self-generated Error Message Containing Sensitive Information",
    "CWE-212": "Improper Cross-boundary Removal of Sensitive Data",
    "CWE-213": "Exposure of Sensitive Information Due to Incompatible Policies",
    "CWE-256": "Unprotected Storage of Credentials",
    "CWE-259": "Hard-coded Password",
    "CWE-269": "Improper Privilege Management",
    "CWE-270": "Privilege Context Switching Error",
    "CWE-271": "Privilege Dropping / Lowering Errors",
    "CWE-272": "Least Privilege Violation",
    "CWE-273": "Improper Check for Dropped Privileges",
    "CWE-274": "Improper Handling of Insufficient Privileges",
    "CWE-276": "Incorrect Default Permissions",
    "CWE-277": "Insecure Inherited Permissions",
    "CWE-278": "Insecure Preserved Inherited Permissions",
    "CWE-279": "Incorrect Execution-Assigned Permissions",
    "CWE-280": "Improper Handling of Insufficient Permissions or Privileges",
    "CWE-281": "Improper Preservation of Permissions",
    "CWE-284": "Improper Access Control",
    "CWE-285": "Improper Authorization",
    "CWE-287": "Improper Authentication",
    "CWE-288": "Auth Bypass Using Alternate Path",
    "CWE-290": "Auth Bypass by Spoofing",
    "CWE-295": "Improper Certificate Validation",
    "CWE-297": "Improper Hostname Validation",
    "CWE-298": "Improper Validation of Certificate Expiration",
    "CWE-299": "Improper Check for Certificate Revocation",
    "CWE-300": "Channel Accessible by Non-Endpoint",
    "CWE-306": "Missing Auth for Critical Function",
    "CWE-307": "Improper Restriction of Excessive Auth Attempts",
    "CWE-310": "Cryptographic Issues",
    "CWE-311": "Missing Encryption of Sensitive Data",
    "CWE-312": "Cleartext Storage of Sensitive Info",
    "CWE-313": "Cleartext Storage in a File or on Disk",
    "CWE-319": "Cleartext Transmission of Sensitive Info",
    "CWE-320": "Key Management Errors",
    "CWE-321": "Use of Hard-coded Cryptographic Key",
    "CWE-322": "Key Exchange without Entity Authentication",
    "CWE-323": "Reusing a Nonce, Key Pair in Encryption",
    "CWE-324": "Use of a Key Past its Expiration Date",
    "CWE-325": "Missing Required Cryptographic Step",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-328": "Use of Weak Hash",
    "CWE-329": "Not Using a Random IV with CBC Mode",
    "CWE-330": "Use of Insufficiently Random Values",
    "CWE-331": "Insufficient Entropy",
    "CWE-332": "Insufficient Entropy in PRNG",
    "CWE-333": "Improper Handling of Insufficient Entropy in TRNG",
    "CWE-334": "Small Space of Random Values",
    "CWE-335": "Incorrect Usage of Seeds in PRNG",
    "CWE-336": "Same Seed in PRNG",
    "CWE-337": "Predictable Seed in PRNG",
    "CWE-338": "Use of Cryptographically Weak PRNG",
    "CWE-339": "Small Seed Space in PRNG",
    "CWE-340": "Generation of Predictable Numbers or Identifiers",
    "CWE-341": "Predictable from Observable State",
    "CWE-345": "Insufficient Verification of Data Authenticity",
    "CWE-346": "Origin Validation Error",
    "CWE-347": "Improper Verification of Cryptographic Signature",
    "CWE-349": "Acceptance of Extraneous Untrusted Data With Trusted Data",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-354": "Improper Validation of Integrity Check Value",
    "CWE-358": "Improperly Implemented Security Check for Standard",
    "CWE-359": "Privacy Violation",
    "CWE-362": "Race Condition",
    "CWE-369": "Divide By Zero",
    "CWE-370": "Missing Check for Certificate Revocation after Initial Check",
    "CWE-371": "State Issues",
    "CWE-372": "Incomplete Internal State Distinction",
    "CWE-374": "Passing Mutable Objects to an Untrusted Method",
    "CWE-375": "Returning a Mutable Object to an Untrusted Caller",
    "CWE-377": "Insecure Temporary File",
    "CWE-378": "Creation of Temporary File With Insecure Permissions",
    "CWE-379": "Creation of Temporary File in Directory with Incorrect Permissions",
    "CWE-384": "Session Fixation",
    "CWE-385": "Covert Timing Channel",
    "CWE-390": "Detection of Error Condition Without Action",
    "CWE-391": "Unchecked Error Condition",
    "CWE-392": "Missing Report of Error Condition",
    "CWE-393": "Return of Wrong Status Code",
    "CWE-394": "Unexpected Status Code or Return Value",
    "CWE-395": "Use of NullPointerException Catch to Detect NULL Pointer Dereference",
    "CWE-396": "Declaration of Catch for Generic Exception",
    "CWE-397": "Declaration of Throws for Generic Exception",
    "CWE-398": "Indicator of Poor Code Quality",
    "CWE-399": "Resource Management Errors",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-401": "Missing Release of Memory after Effective Lifetime",
    "CWE-402": "Transmission of Private Resources into a New Sphere",
    "CWE-403": "Exposure of File Descriptor to Unintended Control Sphere",
    "CWE-404": "Improper Resource Shutdown or Release",
    "CWE-405": "Asymmetric Resource Consumption (Amplification)",
    "CWE-406": "Insufficient Control of Network Message Volume",
    "CWE-407": "Algorithmic Complexity",
    "CWE-408": "Incorrect Behavior Order: Early Amplification",
    "CWE-409": "Improper Handling of Highly Compressed Data",
    "CWE-410": "Insufficient Resource Pool",
    "CWE-411": "Resource Locking Problems",
    "CWE-412": "Unrestricted Externally Accessible Lock",
    "CWE-413": "Improper Resource Locking",
    "CWE-414": "Missing Lock Check",
    "CWE-415": "Double Free",
    "CWE-416": "Use After Free",
    "CWE-417": "Communication Channel Errors",
    "CWE-418": "Externally Controlled Network Settings",
    "CWE-419": "Unprotected Primary Channel",
    "CWE-420": "Unprotected Alternate Channel",
    "CWE-421": "Race Condition During Access to Alternate Channel",
    "CWE-422": "Unprotected Windows Messaging Channel",
    "CWE-423": "DEPRECATED: Proxied Trusted Channel",
    "CWE-424": "Improper Protection of Alternate Path",
    "CWE-425": "Direct Request ('Forced Browsing')",
    "CWE-426": "Untrusted Search Path",
    "CWE-427": "Uncontrolled Search Path Element",
    "CWE-428": "Unquoted Search Path or Element",
    "CWE-430": "Deployment of Wrong Handler",
    "CWE-431": "Missing Handler",
    "CWE-432": "Dangerous Signal Handler not Disabled During Sensitive Operations",
    "CWE-433": "Unparsed Raw Web Content Delivery",
    "CWE-434": "Unrestricted Upload of File with Dangerous Type",
    "CWE-435": "Improper Interaction Between Multiple Correctly-Behaving Entities",
    "CWE-436": "Interpretation Conflict",
    "CWE-437": "Incomplete Model of Endpoint Features",
    "CWE-439": "Behavioral Change in New Version or Environment",
    "CWE-440": "Expected Behavior Violation",
    "CWE-441": "Unintended Proxy or Intermediary",
    "CWE-444": "HTTP Request Smuggling",
    "CWE-446": "UI Discrepancy for Security Feature",
    "CWE-447": "Unimplemented or Unsupported Feature in UI",
    "CWE-448": "Obsolete Feature in UI",
    "CWE-449": "The UI Performs the Wrong Action",
    "CWE-450": "Multiple Interpretations of UI Input",
    "CWE-451": "UI Misrepresentation of Critical Information",
    "CWE-453": "Insecure Default Variable Initialization",
    "CWE-454": "External Initialization of Trusted Variables or Data Stores",
    "CWE-455": "Non-exit on Failed Initialization",
    "CWE-456": "Missing Initialization of a Variable",
    "CWE-457": "Use of Uninitialized Variable",
    "CWE-459": "Incomplete Cleanup",
    "CWE-460": "Improper Cleanup on Thrown Exception",
    "CWE-462": "Duplicate Key in Associative List",
    "CWE-463": "Deletion of Data Structure Sentinel",
    "CWE-464": "Addition of Data Structure Sentinel",
    "CWE-466": "Return of Pointer Value Outside of Expected Range",
    "CWE-467": "Use of sizeof() on a Pointer Type",
    "CWE-468": "Incorrect Pointer Scaling",
    "CWE-469": "Use of Pointer Subtraction to Determine Size",
    "CWE-470": "Use of Externally-Controlled Input to Select Classes or Code",
    "CWE-471": "Modification of Assumed-Immutable Data (MAID)",
    "CWE-472": "External Control of Assumed-Immutable Web Parameter",
    "CWE-473": "PHP External Variable Modification",
    "CWE-474": "Use of Function with Inconsistent Implementations",
    "CWE-475": "Undefined Behavior for Input to API",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-477": "Use of Obsolete Function",
    "CWE-478": "Missing Default Case in Switch Statement",
    "CWE-479": "Signal Handler Use of a Non-reentrant Function",
    "CWE-480": "Use of Incorrect Operator",
    "CWE-481": "Assigning instead of Comparing",
    "CWE-482": "Comparing instead of Assigning",
    "CWE-483": "Incorrect Block Delimitation",
    "CWE-484": "Omitted Break Statement in Switch",
    "CWE-486": "Comparison of Classes by Name",
    "CWE-487": "Reliance on Package-level Scope",
    "CWE-488": "Exposure of Data Element to Wrong Session",
    "CWE-489": "Active Debug Code",
    "CWE-491": "Public cloneable() Method Without Final ('Object Hijack')",
    "CWE-492": "Use of Inner Class Containing Sensitive Data",
    "CWE-493": "Critical Public Variable Without Final Modifier",
    "CWE-494": "Download of Code Without Integrity Check",
    "CWE-495": "Private Data Structure Returned From A Public Method",
    "CWE-496": "Public Data Assigned to Private Array-Typed Field",
    "CWE-497": "Exposure of System Data to an Unauthorized Control Sphere",
    "CWE-498": "Cloneable Class Containing Sensitive Information",
    "CWE-499": "Serializable Class Containing Sensitive Data",
    "CWE-500": "Public Static Field Not Marked Final",
    "CWE-501": "Trust Boundary Violation",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-506": "Embedded Malicious Code",
    "CWE-507": "Trojan Horse",
    "CWE-508": "Non-Replicating Malicious Code",
    "CWE-509": "Replicating Malicious Code (Virus or Worm)",
    "CWE-510": "Trapdoor",
    "CWE-511": "Logic/Time Bomb",
    "CWE-512": "Spyware",
    "CWE-514": "Covert Channel",
    "CWE-515": "Covert Storage Channel",
    "CWE-521": "Weak Password Requirements",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-523": "Unprotected Transport of Credentials",
    "CWE-524": "Use of Cache Containing Sensitive Information",
    "CWE-525": "Use of Web Browser Cache Containing Sensitive Information",
    "CWE-526": "Cleartext Storage of Sensitive Information in an Environment Variable",
    "CWE-527": "Exposure of Version-Control Repository to an Unauthorized Actor",
    "CWE-528": "Exposure of Core Dump File to an Unauthorized Actor",
    "CWE-529": "Exposure of Access Control List Files to an Unauthorized Actor",
    "CWE-530": "Exposure of Backup File to an Unauthorized Actor",
    "CWE-531": "Inclusion of Sensitive Information in Test Code",
    "CWE-532": "Insertion of Sensitive Information into Log File",
    "CWE-538": "Insertion of Sensitive Information into Externally-Accessible File or Directory",
    "CWE-539": "Use of Persistent Cookies Containing Sensitive Information",
    "CWE-540": "Inclusion of Sensitive Information in Source Code",
    "CWE-541": "Inclusion of Sensitive Information in an Include File",
    "CWE-543": "Use of Singleton Pattern Without Synchronization in a Multithreaded Context",
    "CWE-544": "Missing Standardized Error Handling Mechanism",
    "CWE-545": "Use of Dynamic Class Loading",
    "CWE-546": "Suspicious Comment",
    "CWE-547": "Use of Hard-coded, Security-relevant Constants",
    "CWE-548": "Exposure of Information Through Directory Listing",
    "CWE-549": "Missing Password Field Masking",
    "CWE-550": "Server-generated Error Message Containing Sensitive Information",
    "CWE-551": "Incorrect Behavior Order: Authorization Before Parsing and Canonicalization",
    "CWE-552": "Files or Directories Accessible to External Parties",
    "CWE-553": "Command Shell in Externally Accessible Directory",
    "CWE-554": "ASP.NET Misconfiguration: Not Using Input Validation Framework",
    "CWE-555": "J2EE Misconfiguration: Plaintext Password in Configuration File",
    "CWE-556": "ASP.NET Misconfiguration: Use of Identity Impersonation",
    "CWE-558": "Use of getlogin() in Multithreaded Application",
    "CWE-560": "Use of umask() with chmod-style Argument",
    "CWE-561": "Dead Code",
    "CWE-562": "Return of Stack Variable Address",
    "CWE-563": "Assignment to Variable without Use ('Unused Variable')",
    "CWE-564": "SQL Injection: Hibernate",
    "CWE-565": "Reliance on Cookies without Validation and Integrity Checking",
    "CWE-566": "Authorization Bypass Through User-Controlled SQL Primary Key",
    "CWE-567": "Unsynchronized Access to Shared Data in a Multithreaded Context",
    "CWE-568": "finalize() Method Without super.finalize()",
    "CWE-570": "Expression is Always False",
    "CWE-571": "Expression is Always True",
    "CWE-572": "Call to Thread run() instead of start()",
    "CWE-573": "Improper Following of Specification by Caller",
    "CWE-574": "EJB Bad Practices: Use of Synchronization Primitives",
    "CWE-575": "EJB Bad Practices: Use of AWT Swing",
    "CWE-576": "EJB Bad Practices: Use of Java I/O",
    "CWE-577": "EJB Bad Practices: Use of Sockets",
    "CWE-578": "EJB Bad Practices: Use of Class Loader",
    "CWE-579": "J2EE Bad Practices: Non-serializable Object Stored in Session",
    "CWE-580": "clone() Method Without super.clone()",
    "CWE-581": "Object Model Violation: Just One of Equals and Hashcode Defined",
    "CWE-582": "Array Declared Public, Final, and Static",
    "CWE-583": "finalize() Method Declared Public",
    "CWE-584": "Return Inside Finally Block",
    "CWE-585": "Empty Synchronized Block",
    "CWE-586": "Explicit Call to Finalize()",
    "CWE-587": "Assignment of a Fixed Address to a Pointer",
    "CWE-588": "Attempt to Access Child of a Non-structure Pointer",
    "CWE-589": "Call to Non-ubiquitous API",
    "CWE-590": "Free of Memory not on the Heap",
    "CWE-591": "Sensitive Data Storage in Improperly Locked Memory",
    "CWE-593": "Authentication Bypass: OpenSSL CTX Object Modified after SSL Objects are Created",
    "CWE-594": "J2EE Framework: Saving Non-Serializable Objects to Disk",
    "CWE-595": "Comparison of Object References Instead of Object Contents",
    "CWE-596": "DEPRECATED: Incorrect Semantic Object Comparison",
    "CWE-597": "Use of Wrong Operator in String Comparison",
    "CWE-598": "Use of GET Request Method With Sensitive Query Strings",
    "CWE-599": "Missing Validation of OpenSSL Certificate",
    "CWE-601": "Open Redirect",
    "CWE-602": "Client-Side Enforcement of Server-Side Security",
    "CWE-603": "Use of Client-Side Authentication",
    "CWE-605": "Multiple Binds to the Same Port",
    "CWE-606": "Unchecked Input for Loop Condition",
    "CWE-607": "Public Static Final Field References Mutable Object",
    "CWE-608": "Struts: Non-private Field in ActionForm Class",
    "CWE-609": "Double-Checked Locking",
    "CWE-610": "Externally Controlled Reference to a Resource in Another Sphere",
    "CWE-611": "XML External Entity Reference",
    "CWE-612": "Improper Authorization of Index Containing Sensitive Information",
    "CWE-613": "Insufficient Session Expiration",
    "CWE-614": "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
    "CWE-615": "Inclusion of Sensitive Information in Source Code Comments",
    "CWE-616": "Incomplete Identification of Uploaded File Variables",
    "CWE-617": "Reachable Assertion",
    "CWE-618": "Exposed Unsafe ActiveX Method",
    "CWE-619": "Dangling Database Cursor ('Cursor Injection')",
    "CWE-620": "Unverified Password Change",
    "CWE-621": "Variable Extraction Error",
    "CWE-622": "Improper Validation of Function Hook Arguments",
    "CWE-623": "Unsafe ActiveX Control Marked Safe For Scripting",
    "CWE-624": "Executable Regular Expression Error",
    "CWE-625": "Permissive Regular Expression",
    "CWE-626": "Null Byte Interaction Error (Poison Null Byte)",
    "CWE-627": "Dynamic Variable Evaluation",
    "CWE-628": "Function Call with Incorrectly Specified Arguments",
    "CWE-636": "Not Failing Securely ('Failing Open')",
    "CWE-637": "Unnecessary Complexity in Protection Mechanism",
    "CWE-638": "Not Using Complete Mediation",
    "CWE-639": "Authorization Bypass Through User-Controlled Key",
    "CWE-640": "Weak Password Recovery Mechanism for Forgotten Password",
    "CWE-641": "Improper Restriction of Names for Files and Other Resources",
    "CWE-642": "External Control of Critical State Data",
    "CWE-643": "Improper Neutralization of Data within XPath Expressions ('XPath Injection')",
    "CWE-644": "Improper Neutralization of HTTP Headers for Scripting Syntax",
    "CWE-645": "Overly Restrictive Account Lockout Mechanism",
    "CWE-646": "Reliance on File Name or Extension of Externally-Supplied File",
    "CWE-647": "Use of Non-Canonical URL Paths for Authorization Decisions",
    "CWE-648": "Incorrect Use of Privileged APIs",
    "CWE-649": "Reliance on Obfuscation or Encryption of Security-Relevant Inputs without Integrity Checking",
    "CWE-650": "Trusting HTTP Permission Methods on the Server Side",
    "CWE-651": "Exposure of WSDL File Containing Sensitive Information",
    "CWE-652": "Improper Neutralization of Data within XQuery Expressions ('XQuery Injection')",
    "CWE-653": "Insufficient Compartmentalization",
    "CWE-654": "Reliance on a Single Factor in a Security Decision",
    "CWE-655": "Insufficient Psychological Acceptability",
    "CWE-656": "Reliance on Security Through Obscurity",
    "CWE-657": "Violation of Secure Design Principles",
    "CWE-662": "Improper Synchronization",
    "CWE-664": "Improper Control of a Resource Through its Lifetime",
    "CWE-665": "Improper Initialization",
    "CWE-667": "Improper Locking",
    "CWE-668": "Exposure of Resource to Wrong Sphere",
    "CWE-669": "Incorrect Resource Transfer Between Spheres",
    "CWE-670": "Always-Incorrect Control Flow Implementation",
    "CWE-671": "Lack of Administrator Control over Security",
    "CWE-672": "Operation on a Resource after Expiration or Release",
    "CWE-673": "External Influence of Sphere Definition",
    "CWE-674": "Uncontrolled Recursion",
    "CWE-675": "Multiple Operations on Resource in Single-Operation Context",
    "CWE-676": "Use of Potentially Dangerous Function",
    "CWE-680": "Integer Overflow to Buffer Overflow",
    "CWE-681": "Incorrect Conversion between Numeric Types",
    "CWE-682": "Incorrect Calculation",
    "CWE-685": "Function Call With Incorrect Number of Arguments",
    "CWE-686": "Function Call With Incorrect Argument Type",
    "CWE-687": "Function Call With Incorrectly Specified Argument Value",
    "CWE-688": "Function Call With Incorrect Variable or Reference as Argument",
    "CWE-689": "Permission Race Condition During Resource Copy",
    "CWE-690": "Unchecked Return Value to NULL Pointer Dereference",
    "CWE-691": "Insufficient Control Flow Management",
    "CWE-693": "Protection Mechanism Failure",
    "CWE-694": "Use of Multiple Resources with Duplicate Identifier",
    "CWE-695": "Use of Low-Level Functionality",
    "CWE-696": "Incorrect Behavior Order",
    "CWE-697": "Incorrect Comparison",
    "CWE-698": "Execution After Redirect (EAR)",
    "CWE-703": "Improper Check or Handling of Exceptional Conditions",
    "CWE-704": "Incorrect Type Conversion or Cast",
    "CWE-705": "Incorrect Control Flow Scoping",
    "CWE-706": "Use of Incorrectly-Resolved Name or Reference",
    "CWE-707": "Improper Neutralization",
    "CWE-708": "Incorrect Ownership Assignment",
    "CWE-710": "Improper Adherence to Coding Standards",
    "CWE-732": "Incorrect Permission Assignment for Critical Resource",
    "CWE-733": "Compiler Optimization Removal or Modification of Security-critical Code",
    "CWE-749": "Exposed Dangerous Method or Function",
    "CWE-754": "Improper Check for Unusual or Exceptional Conditions",
    "CWE-755": "Improper Handling of Exceptional Conditions",
    "CWE-756": "Missing Custom Error Page",
    "CWE-757": "Selection of Less-Secure Algorithm During Negotiation ('Algorithm Downgrade')",
    "CWE-758": "Reliance on Undefined, Unspecified, or Implementation-Defined Behavior",
    "CWE-759": "Use of a One-Way Hash without a Salt",
    "CWE-760": "Use of a One-Way Hash with a Predictable Salt",
    "CWE-761": "Free of Pointer not at Start of Buffer",
    "CWE-762": "Mismatched Memory Management Routines",
    "CWE-763": "Release of Invalid Pointer or Reference",
    "CWE-764": "Multiple Locks of a Critical Resource",
    "CWE-765": "Multiple Unlocks of a Critical Resource",
    "CWE-766": "Critical Data Element Declared Public",
    "CWE-767": "Access to Critical Private Variable via Public Method",
    "CWE-768": "Incorrect Short Circuit Evaluation",
    "CWE-769": "DEPRECATED: Uncontrolled File Descriptor Consumption",
    "CWE-770": "Allocation of Resources Without Limits or Throttling",
    "CWE-771": "Missing Reference to Active Allocated Resource",
    "CWE-772": "Missing Release of Resource after Effective Lifetime",
    "CWE-773": "Missing Reference to Active File Descriptor or Handle",
    "CWE-774": "Allocation of File Descriptors or Handles Without Limits or Throttling",
    "CWE-775": "Missing Release of File Descriptor or Handle after Effective Lifetime",
    "CWE-776": "Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')",
    "CWE-777": "Regular Expression without Anchors",
    "CWE-778": "Insufficient Logging",
    "CWE-779": "Logging of Excessive Data",
    "CWE-780": "Use of RSA Algorithm without OAEP",
    "CWE-781": "Improper Address Validation in OGNL expressions",
    "CWE-782": "Exposed IOCTL with Insufficient Access Control",
    "CWE-783": "Operator Precedence Logic Error",
    "CWE-784": "Reliance on Cookies without Validation and Integrity Checking in a Security Decision",
    "CWE-785": "Use of Path Manipulation Function without Maximum-sized Buffer",
    "CWE-786": "Access of Memory Location Before Start of Buffer",
    "CWE-787": "Out-of-bounds Write",
    "CWE-788": "Access of Memory Location After End of Buffer",
    "CWE-789": "Memory Allocation with Excessive Size Value",
    "CWE-790": "Improper Filtering of Special Elements",
    "CWE-791": "Incomplete Filtering of Special Elements",
    "CWE-792": "Incomplete Filtering of One or More Instances of Special Elements",
    "CWE-793": "Only Filtering One Instance of a Special Element",
    "CWE-794": "Incomplete Filtering of Multiple Instances of Special Elements from the Same Category",
    "CWE-795": "Only Filtering Special Elements at a Specified Location",
    "CWE-796": "Only Filtering Special Elements Relative to a Marker",
    "CWE-797": "Only Filtering Special Elements at an Absolute Position",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-799": "Improper Control of Interaction Frequency",
    "CWE-804": "Guessable CAPTCHA",
    "CWE-805": "Buffer Access with Incorrect Length Value",
    "CWE-806": "Buffer Access Using Size of Source Buffer",
    "CWE-807": "Reliance on Untrusted Inputs in a Security Decision",
    "CWE-820": "Missing Synchronization",
    "CWE-821": "Incorrect Synchronization",
    "CWE-822": "Untrusted Pointer Dereference",
    "CWE-823": "Use of Out-of-range Pointer Offset",
    "CWE-824": "Access of Uninitialized Pointer",
    "CWE-825": "Expired Pointer Dereference",
    "CWE-826": "Premature Release of Resource During Expected Lifetime",
    "CWE-827": "Improper Control of Document Type Definition",
    "CWE-828": "Signal Handler with Functionality that is not Asynchronous-Safe",
    "CWE-829": "Inclusion of Functionality from Untrusted Control Sphere",
    "CWE-830": "Inclusion of Web Functionality from an Untrusted Source",
    "CWE-831": "Signal Handler Function Associated with Multiple Signals",
    "CWE-832": "Unlock of a Resource that is not Locked",
    "CWE-833": "Deadlock",
    "CWE-834": "Excessive Iteration",
    "CWE-835": "Loop with Unreachable Exit Condition ('Infinite Loop')",
    "CWE-836": "Use of Password Hash Instead of Password for Authentication",
    "CWE-837": "Improper Enforcement of a Single, Unique Action",
    "CWE-838": "Inappropriate Encoding for Output Context",
    "CWE-839": "Numeric Range Comparison Without Minimum Check",
    "CWE-841": "Improper Enforcement of Behavioral Workflow",
    "CWE-842": "Placement of User into Incorrect Group",
    "CWE-843": "Access of Resource Using Incompatible Type ('Type Confusion')",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-908": "Use of Uninitialized Resource",
    "CWE-909": "Missing Initialization of Resource",
    "CWE-910": "Use of Expired File Descriptor",
    "CWE-911": "Improper Update of Reference Count",
    "CWE-912": "Hidden Functionality",
    "CWE-913": "Improper Control of Dynamically-Managed Code Resources",
    "CWE-914": "Improper Control of Dynamically-Identified Variables",
    "CWE-915": "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
    "CWE-916": "Use of Password Hash With Insufficient Computational Effort",
    "CWE-917": "Server-Side Template Injection",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-920": "Improper Restriction of Power Consumption",
    "CWE-921": "Storage of Sensitive Data in a Mechanism without Access Control",
    "CWE-922": "Insecure Storage of Sensitive Information",
    "CWE-923": "Improper Restriction of Communication Channel to Intended Endpoints",
    "CWE-924": "Improper Enforcement of Message Integrity During Transmission in a Communication Channel",
    "CWE-925": "Improper Verification of Intent by Broadcast Receiver",
    "CWE-926": "Improper Export of Android Application Components",
    "CWE-927": "Use of Implicit Intent for Sensitive Communication",
    "CWE-939": "Improper Authorization in Handler for Custom URL Scheme",
    "CWE-940": "Improper Verification of Source of a Communication Channel",
    "CWE-941": "Incorrectly Specified Destination in a Communication Channel",
    "CWE-942": "Permissive Cross-domain Policy with Untrusted Domains",
    "CWE-943": "Improper Neutralization of Special Elements in Data Query Logic",
    "CWE-1004": "Sensitive Cookie Without 'HttpOnly' Flag",
    "CWE-1007": "Insufficient Visual Distinction of Homoglyphs",
    "CWE-1021": "Improper Restriction of Rendered UI Layers or Frames",
    "CWE-1022": "Use of Web Link to Untrusted Target with window.opener Access",
    "CWE-1025": "Comparison Using Wrong Factors",
    "CWE-1035": "OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities",
    "CWE-1037": "Processor Optimization Removal or Modification of Security-critical Code",
    "CWE-1038": "Insecure Automated Optimizations",
    "CWE-1039": "Automated Recognition Mechanism with Inadequate Detection or Handling of Adversarial Input Variations",
    "CWE-1041": "Use of Redundant Code",
    "CWE-1042": "Static Member Data Element outside of a Singleton Class Element",
    "CWE-1043": "Data Element Aggregating an Excessively Large Number of Non-Primitive Elements",
    "CWE-1044": "Architecture with Number of Horizontal Layers Outside of Expected Range",
    "CWE-1045": "Parent Class with a Virtual Destructor and a Child Class without a Virtual Destructor",
    "CWE-1046": "Creation of Immutable Text Using String Concatenation",
    "CWE-1047": "Modules with Circular Dependencies",
    "CWE-1048": "Invokable Control Element with Large Number of Outward Calls",
    "CWE-1049": "Excessive Data Query Operations in a Large Data Table",
    "CWE-1050": "Excessive Platform Resource Consumption within a Loop",
    "CWE-1051": "Initialization with Hard-Coded Network Resource Configuration Data",
    "CWE-1052": "Excessive Use of Hard-Coded Literals in Initialization",
    "CWE-1053": "Missing Documentation for Design",
    "CWE-1054": "Invocation of a Control Element at an Unnecessarily Deep Horizontal Layer",
    "CWE-1055": "Multiple Inheritance from Concrete Classes",
    "CWE-1056": "Invokable Control Element with Variadic Parameters",
    "CWE-1057": "Data Access Operations Outside of Expected Data Manager Component",
    "CWE-1058": "Invokable Control Element in Multi-Thread Context with non-MT-Safe Implementation",
    "CWE-1059": "Insufficient Technical Documentation",
    "CWE-1060": "Excessive Number of Inefficient Server-Side Data Accesses",
    "CWE-1061": "Insufficient Encapsulation",
    "CWE-1062": "Parent Class with References to Child Class",
    "CWE-1063": "Creation of Class Instance within a Static Code Block",
    "CWE-1064": "Invokable Control Element with Signature Containing an Excessive Number of Parameters",
    "CWE-1065": "Runtime Resource Management Control Element in a Component Built to Run on Application Servers",
    "CWE-1066": "Missing Serialization Control Element",
    "CWE-1067": "Excessive Execution of Sequential Searches of Data Resource",
    "CWE-1068": "Inconsistency Between Implementation and Documented Design",
    "CWE-1069": "Empty Exception Block",
    "CWE-1070": "Serializable Data Element Containing non-Serializable Item Elements",
    "CWE-1071": "Empty Code Block",
    "CWE-1072": "Data Resource Access without Use of Connection Pooling",
    "CWE-1073": "Non-SQL Invokable Control Element with Excessive Number of Data Resource Accesses",
    "CWE-1074": "Class with Excessively Deep Inheritance",
    "CWE-1075": "Unconditional Control Flow Transfer outside of Switch Block",
    "CWE-1076": "Insufficient Adherence to Expected Conventions",
    "CWE-1077": "Floating Point Comparison with Incorrect Operator",
    "CWE-1078": "Inappropriate Source Code Style or Formatting",
    "CWE-1079": "Parent Class without Virtual Destructor",
    "CWE-1080": "Source Code File with Excessive Number of Lines of Code",
    "CWE-1082": "Class Instance Self Destruction Control Element",
    "CWE-1083": "Data Access from Outside Expected Data Manager Component",
    "CWE-1084": "Invokable Control Element with Excessive File or Data Access Operations",
    "CWE-1085": "Invokable Control Element with Excessive Volume of Commented-out Code",
    "CWE-1086": "Invokable Control Element with Excessive Number of Child Elements",
    "CWE-1087": "Class with Virtual Method without a Virtual Destructor",
    "CWE-1088": "Synchronous Access of Remote Resource without Timeout",
    "CWE-1089": "Large Data Table with Excessive Number of Indices",
    "CWE-1090": "Method Containing Access of a Member Element from Another Class",
    "CWE-1091": "Use of Object without Invoking Destructor Method",
    "CWE-1092": "Use of Same Invokable Control Element in Multiple Architectural Layers",
    "CWE-1093": "Excessively Complex Data Representation",
    "CWE-1094": "Excessive Index Range Scan for a Data Resource",
    "CWE-1095": "Loop Condition Value Update within the Loop",
    "CWE-1096": "Singleton Class Instance Creation without Proper Locking or Checkup",
    "CWE-1097": "Persistent Storable Data Element without Associated Comparison Control Element",
    "CWE-1098": "Data Element containing Pointer Item without Proper Copy Control Element",
    "CWE-1099": "Inconsistent Naming Conventions for Identifiers",
    "CWE-1100": "Insufficient Isolation of System-Dependent Functions",
    "CWE-1101": "Reliance on Runtime Component in Generated Code",
    "CWE-1102": "Reliance on Machine-Dependent Data Representation",
    "CWE-1103": "Use of Platform-Dependent Third Party Components",
    "CWE-1104": "Use of Unmaintained Third Party Components",
    "CWE-1105": "Insufficient Encapsulation of Machine-Dependent Functionality",
    "CWE-1106": "Insufficient Use of Symbolic Constants",
    "CWE-1107": "Insufficient Isolation of Symbolic Constant Definitions",
    "CWE-1108": "Excessive Reliance on Global Variables",
    "CWE-1109": "Use of Same Variable for Multiple Purposes",
    "CWE-1110": "Incomplete Design Documentation",
    "CWE-1111": "Incomplete I/O Documentation",
    "CWE-1112": "Incomplete Documentation of Program Execution",
    "CWE-1113": "Inappropriate Comment Style",
    "CWE-1114": "Inappropriate Whitespace Style",
    "CWE-1115": "Source Code Element without Standard Prologue",
    "CWE-1116": "Inaccurate Comments",
    "CWE-1117": "Callable with Insufficient Behavioral Summary",
    "CWE-1118": "Insufficient Documentation of Error Handling Techniques",
    "CWE-1119": "Excessive Use of Unconditional Branching",
    "CWE-1120": "Excessive Code Complexity",
    "CWE-1121": "Excessive McCabe Cyclomatic Complexity",
    "CWE-1122": "Excessive Halstead Complexity",
    "CWE-1123": "Excessive Use of Self-Modifying Code",
    "CWE-1124": "Excessively Deep Nesting",
    "CWE-1125": "Excessive Attack Surface",
    "CWE-1126": "Declaration of Variable with Unnecessarily Wide Scope",
    "CWE-1127": "Compilation with Insufficient Warnings or Errors",
    "CWE-1173": "Improper Use of Validation Framework",
    "CWE-1174": "ASP.NET Misconfiguration: Improper Model Validation",
    "CWE-1176": "Inefficient CPU Computation",
    "CWE-1177": "Use of Prohibited Code",
    "CWE-1187": "DEPRECATED: Use of Uninitialized Resource",
    "CWE-1188": "Initialization of a Resource with an Insecure Default",
    "CWE-1189": "Improper Isolation of Shared Resources on Network On a Chip (NoC)",
    "CWE-1190": "DMA Device Enabled Too Early in Boot Phase",
    "CWE-1191": "On-Chip Debug and Test Interface With Improper Access Control",
    "CWE-1192": "System-on-Chip (SoC) Using Components without Unique, Immutable Identifiers",
    "CWE-1193": "Power-On of Untrusted Execution Core Before Enabling Fabric Access Control",
    "CWE-1220": "Insufficient Granularity of Access Control",
    "CWE-1221": "Incorrect Register Defaults or Module Parameters",
    "CWE-1222": "Insufficient Granularity of Address Regions Protected by Register Locks",
    "CWE-1223": "Race Condition for Write-Once Attributes",
    "CWE-1224": "Improper Restriction of Write-Once Bit Fields",
    "CWE-1230": "Exposure of Sensitive Information Through Metadata",
    "CWE-1231": "Improper Prevention of Lock Bit Modification",
    "CWE-1232": "Improper Lock Behavior After Power State Transition",
    "CWE-1233": "Security-Sensitive Hardware Controls with Missing Lock Bit Protection",
    "CWE-1234": "Hardware Internal or Debug Modes Allow Override of Locks",
    "CWE-1235": "Incorrect Use of Autostart Execution",
    "CWE-1236": "Improper Neutralization of Formula Elements in a CSV File",
    "CWE-1239": "Improper Zeroization of Hardware Register",
    "CWE-1240": "Use of a Cryptographic Primitive with a Risky Implementation",
    "CWE-1241": "Use of Predictable Algorithm in Random Number Generator",
    "CWE-1242": "Inclusion of Undocumented Features or Chicken Bits",
    "CWE-1243": "Sensitive Non-Volatile Information Not Protected During Debug",
    "CWE-1244": "Internal Asset Exposed to Unsafe Debug Access Level or State",
    "CWE-1245": "Improper Finite State Machines (FSMs) in Hardware Logic",
    "CWE-1246": "Improper Write Handling in Limited-write Non-Volatile Memories",
    "CWE-1247": "Improper Protection Against Voltage and Clock Glitches",
    "CWE-1248": "Semiconductor Defects in Hardware Logic with Security-Sensitive Implications",
    "CWE-1249": "Application-Level Admin Tool with Inconsistent View of Underlying Operating System",
    "CWE-1250": "Improper Preservation of Consistency Between Independent Representations of Shared State",
    "CWE-1251": "Mirrored Regions with Different Values",
    "CWE-1252": "CPU Hardware Not Configured to Support Exclusivity of Write and Execute Operations",
    "CWE-1253": "Incorrect Selection of Fuse Values",
    "CWE-1254": "Incorrect Comparison Logic Granularity",
    "CWE-1255": "Comparison Logic is Vulnerable to Power Side-Channel Attacks",
    "CWE-1256": "Improper Restriction of Software Interfaces to Hardware Features",
    "CWE-1257": "Improper Access Control Applied to Mirrored or Aliased Memory Regions",
    "CWE-1258": "Exposure of Confidential Data due to Inconsistent Traffic Filtering",
    "CWE-1259": "Improper Restriction of Security Token Assignment",
    "CWE-1260": "Improper Handling of Overlap Between Protected Memory Ranges",
    "CWE-1261": "Improper Handling of Single Event Upsets",
    "CWE-1262": "Improper Access Control for Register Interface",
    "CWE-1263": "Improper Physical Access Control",
    "CWE-1264": "Hardware Logic with Insecure De-Synchronization between Control and Data Channels",
    "CWE-1265": "Unintended Reentrant Invocation of Non-reentrant Code Via Nested Calls",
    "CWE-1266": "Improper Scrubbing of Sensitive Data from Decommissioned Device",
    "CWE-1267": "Policy Uses Obsolete Encoding",
    "CWE-1268": "Policy Privileges are not Assigned Consistently Between Control and Data Agents",
    "CWE-1269": "Product Released in Non-Release Configuration",
    "CWE-1270": "Generation of Incorrect Security Tokens",
    "CWE-1271": "Uninitialized Value on Reset for Registers Holding Security Settings",
    "CWE-1272": "Sensitive Information Uncleared Before Debug/Power State Transition",
    "CWE-1273": "Device Unlock Credential Sharing",
    "CWE-1274": "Improper Access Control for Volatile Memory Containing Boot Code",
    "CWE-1275": "Sensitive Cookie with Improper SameSite Attribute",
    "CWE-1276": "Hardware Child Block Incorrectly Connected to Parent System",
    "CWE-1277": "Firmware Not Updateable",
    "CWE-1278": "Missing Protection Against Hardware Reverse Engineering Using Integrated Circuit (IC) Inspection Techniques",
    "CWE-1279": "Cryptographic Operations are run Before Supporting Units are Ready",
    "CWE-1280": "Access Control Check Implemented After Asset is Accessed",
    "CWE-1281": "Sequence of Processor Instructions Leads to Unexpected Behavior",
    "CWE-1282": "Assumed-Immutable Data is Stored in Writable Memory",
    "CWE-1283": "Mutable Attestation or Measurement Reporting Data",
    "CWE-1284": "Improper Validation of Specified Quantity in Input",
    "CWE-1285": "Improper Validation of Specified Index, Position, or Offset in Input",
    "CWE-1286": "Improper Validation of Syntactic Correctness of Input",
    "CWE-1287": "Improper Validation of Specified Type of Input",
    "CWE-1288": "Improper Validation of Consistency within Input",
    "CWE-1289": "Improper Validation of Unsafe Equivalence in Input",
    "CWE-1290": "Incorrect Decoding of Security Identifiers",
    "CWE-1291": "Public Key Re-Use for Signing both Debug and Production Code",
    "CWE-1292": "Incorrect Conversion of Security Identifiers",
    "CWE-1293": "Missing Source Correlation of Multiple Independent Data",
    "CWE-1294": "Insecure Security Identifier Mechanism",
    "CWE-1295": "Debug Messages Revealing Unnecessary Information",
    "CWE-1296": "Incorrect Chaining or Granularity of Debug Components",
    "CWE-1297": "Unprotected Confidential Information on Device is Accessible by OSAT Vendors",
    "CWE-1298": "Hardware Logic Contains Race Conditions",
    "CWE-1299": "Missing Protection Mechanism for Alternate Hardware Interface",
    "CWE-1300": "Improper Protection of Physical Side Channels",
    "CWE-1301": "Insufficient or Incomplete Data Removal within Hardware Component",
    "CWE-1302": "Missing Security Identifier",
    "CWE-1303": "Non-Transparent Sharing of Microarchitectural Resources",
    "CWE-1304": "Improperly Preserved Integrity of Hardware Configuration State During a Power Save/Restore Operation",
    "CWE-1310": "Missing Ability to Patch ROM Code",
    "CWE-1311": "Improper Translation of Security Attributes by Fabric Bridge",
    "CWE-1312": "Missing Protection for Mirrored Regions in On-Chip Fabric Firewall",
    "CWE-1313": "Hardware Allows Activation of Test or Debug Logic at Runtime",
    "CWE-1314": "Missing Write Protection for Parametric Data Values",
    "CWE-1315": "Improper Setting of Bus Controlling Capability in Declarative Configuration",
    "CWE-1316": "Fabric-Address Map Allows Programming of Unwarranted Overlaps of Protected and Unprotected Ranges",
    "CWE-1317": "Improper Access Control in Fabric Bridge",
    "CWE-1318": "Missing Support for Security Features in On-chip Fabrics or Buses",
    "CWE-1319": "Improper Protection against Electromagnetic Fault Injection (EM-FI)",
    "CWE-1320": "Improper Protection for Outbound Error Messages and Alert Signals",
    "CWE-1321": "Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')",
    "CWE-1322": "Use of Blocking Code in Single-threaded, Non-blocking Context",
    "CWE-1323": "Improper Management of Sensitive Trace Data",
    "CWE-1324": "DEPRECATED: Sensitive Information Accessible by Physical Probing of JTAG Interface",
    "CWE-1325": "Improperly Controlled Sequential Memory Allocation",
    "CWE-1326": "Missing Immutable Root of Trust in Hardware",
    "CWE-1327": "Binding to an Unrestricted IP Address",
    "CWE-1328": "Security Version Number Mutable to Older Versions",
    "CWE-1329": "Reliance on Component That is Not Updateable",
    "CWE-1330": "Remanent Data Readable after Memory Erase",
    "CWE-1331": "Improper Isolation of Shared Resources in Network On a Chip (NoC)",
    "CWE-1332": "Improper Handling of Faults that Lead to Instruction Skips",
    "CWE-1333": "Inefficient Regular Expression Complexity",
    "CWE-1334": "Unauthorized Error Injection Can Degrade Hardware Redundancy",
    "CWE-1335": "Incorrect Bitwise Shift of Integer",
    "CWE-1336": "Improper Neutralization of Special Elements Used in a Template Engine",
    "CWE-1337": "Improper Handling of Hardware Behavior in Exceptionally Cold Environments",
    "CWE-1338": "Improper Protections Against Hardware Overheating",
    "CWE-1339": "Insufficient Precision or Accuracy of a Real Number",
    "CWE-1341": "Multiple Releases of Same Resource or Handle",
    "CWE-1342": "Information Exposure through Microarchitectural State after Transient Execution",
    "CWE-1351": "Improper Handling of Hardware Behavior in Exceptionally Hot Environments",
    "CWE-1357": "Reliance on Insufficiently Trustworthy Component",
    "CWE-1384": "Improper Handling of Physical or Environmental Conditions",
    "CWE-1385": "Missing Origin Validation in WebSockets",
    "CWE-1386": "Insecure Operation on Windows Junction / Mount Point",
    "CWE-1387": "Reachable non-Public Methods Through Metatransitivity",
    "CWE-1388": "Physical Access Issues and Concerns",
    "CWE-1389": "Incorrect Parsing of Numbers with Different Radices",
    "CWE-1390": "Weak Authentication",
    "CWE-1391": "Use of Weak Credentials",
    "CWE-1392": "Use of Default Credentials",
    "CWE-1393": "Use of Default Password",
    "CWE-1394": "Use of Default Cryptographic Key",
    "CWE-1395": "Dependency on Vulnerable Third-Party Component",
}


def parse_cvss_vector(vector_string):
    """Parse a CVSS v3.x vector string into component dict. Returns {} for CVSS 4.0."""
    if not vector_string or not isinstance(vector_string, str):
        return {}
    # CVSS 4.0 uses different metric keys (AT, VC/VI/VA, SC/SI/SA) — skip to avoid mixing with v3 breakdown
    if vector_string.startswith("CVSS:4.0/"):
        return {}
    parts = vector_string.split("/")
    components = {}
    for part in parts[1:]:
        if ":" in part:
            k, v = part.split(":", 1)
            components[k] = v
    return components


VENDOR_ALIASES = {
    # Microsoft
    "microsoft": "Microsoft",
    "microsoft corporation": "Microsoft",
    # Google
    "google": "Google",
    "google inc.": "Google",
    "google llc": "Google",
    # Oracle
    "oracle": "Oracle",
    "oracle corporation": "Oracle",
    # Apple
    "apple": "Apple",
    "apple inc.": "Apple",
    "apple inc": "Apple",
    # Apache
    "the apache software foundation": "Apache",
    "apache software foundation": "Apache",
    # IBM
    "ibm": "IBM",
    "ibm corporation": "IBM",
    "international business machines corporation": "IBM",
    # Red Hat
    "red hat": "Red Hat",
    "red hat, inc.": "Red Hat",
    "red hat, inc": "Red Hat",
    "redhat": "Red Hat",
    # Qualcomm
    "qualcomm": "Qualcomm",
    "qualcomm, inc.": "Qualcomm",
    "qualcomm technologies, inc.": "Qualcomm",
    # MediaTek
    "mediatek": "MediaTek",
    "mediatek, inc.": "MediaTek",
    # Linux
    "linux": "Linux",
    "linux kernel": "Linux",
}


def parse_cve_file(json_path):
    """Extract enrichment fields from a single CVE JSON file."""
    try:
        with open(json_path, "rb") as f:
            data = orjson.loads(f.read())

        meta = data.get("cveMetadata", {})
        cve_id = meta.get("cveId", "")
        if not cve_id:
            return None

        # Skip REJECTED and RESERVED records — they have no useful enrichment data
        if meta.get("state") in ("REJECTED", "RESERVED"):
            return None

        cna = data.get("containers", {}).get("cna", {})

        # CNA / assigner
        assigner = meta.get("assignerShortName", "")
        if not assigner:
            assigner = cna.get("providerMetadata", {}).get("shortName", "")

        # Vendor / product (first affected entry)
        vendor = ""
        product = ""
        affected = cna.get("affected", [])
        if affected:
            first = affected[0]
            vendor = first.get("vendor", "")
            product = first.get("product", "")
        # Normalize common vendor name variants to canonical form
        vendor = VENDOR_ALIASES.get(vendor.lower().strip(), vendor)

        # CWE (first valid cweId; fallback: some CNAs encode CWE in description text only)
        cwe = ""
        for pt in cna.get("problemTypes", []):
            for desc in pt.get("descriptions", []):
                cid = desc.get("cweId", "")
                if cid and re.match(r"CWE-\d+", cid):
                    cwe = cid
                    break
                # WPScan and similar CNAs set type="CWE" but omit cweId, encoding it in description text
                if not cwe and desc.get("type", "").upper() == "CWE":
                    m = re.search(r"CWE-\d+", desc.get("description", ""))
                    if m:
                        cwe = m.group(0)
                        break
            if cwe:
                break

        # CVSS (prefer CNA, fall back to ADP; prefer v3.1 > v3.0 > v4.0)
        cvss_score = None
        cvss_severity = ""
        cvss_vector = ""

        def extract_cvss(metrics_list):
            for m in metrics_list:
                for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0"):
                    if key in m:
                        entry = m[key]
                        return (
                            entry.get("baseScore"),
                            entry.get("baseSeverity", "").upper(),
                            entry.get("vectorString", ""),
                        )
            return None, "", ""

        cvss_score, cvss_severity, cvss_vector = extract_cvss(cna.get("metrics", []))
        if cvss_score is None:
            for adp in data.get("containers", {}).get("adp", []):
                cvss_score, cvss_severity, cvss_vector = extract_cvss(adp.get("metrics", []))
                if cvss_score is not None:
                    break

        # Description (first English)
        description = ""
        for desc in cna.get("descriptions", []):
            if desc.get("lang", "").startswith("en"):
                description = desc.get("value", "")[:300]
                break

        return {
            "cve": cve_id,
            "cna": assigner,
            "vendor": vendor,
            "product": product,
            "cwe": cwe,
            "cvss_score": cvss_score,
            "cvss_severity": cvss_severity,
            "cvss_vector": cvss_vector,
            "description": description,
        }
    except Exception:
        return None


def _parse_worker(path):
    return parse_cve_file(path)


def load_cve_data(cve_dir: Path) -> pd.DataFrame:
    """Walk cve_dir and build enrichment DataFrame using parallel workers."""
    json_files = list(cve_dir.rglob("CVE-*.json"))
    print(f"Found {len(json_files):,} CVE JSON files", flush=True)

    results = []
    workers = min(os.cpu_count() or 4, 8)
    with ProcessPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_parse_worker, str(p)): p for p in json_files}
        for fut in tqdm(as_completed(futures), total=len(futures), desc="Parsing CVEs", unit="file"):
            r = fut.result()
            if r:
                results.append(r)

    df = pd.DataFrame(results)
    print(f"Parsed {len(df):,} valid CVE records", flush=True)
    return df


def download_epss(url: str, cache_path: Path, no_download: bool) -> pd.DataFrame:
    """Download (or load from cache) a gzipped EPSS CSV."""
    if not no_download or not cache_path.exists():
        print(f"Downloading {url} ...", flush=True)
        resp = requests.get(url, timeout=120)
        resp.raise_for_status()
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_bytes(resp.content)
    else:
        print(f"Using cached {cache_path}", flush=True)

    # Read entire file once; strip all leading comment lines (starts with #)
    with gzip.open(cache_path, "rt") as f:
        raw = f.read()
    while raw.startswith("#"):
        raw = raw[raw.index("\n") + 1:]
    df = pd.read_csv(io.StringIO(raw))

    df.columns = [c.strip() for c in df.columns]
    df["epss"] = pd.to_numeric(df["epss"], errors="coerce")
    df["percentile"] = pd.to_numeric(df["percentile"], errors="coerce")
    return df


def r(v):
    """Round to 5 decimal places; handles None, NaN, and numpy scalars."""
    if pd.isna(v):
        return None
    return round(float(v), 5)


def write_json(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(orjson.dumps(obj, option=orjson.OPT_NON_STR_KEYS))
    print(f"  Wrote {path} ({path.stat().st_size / 1024:.1f} KB)", flush=True)


def build_summary(merged: pd.DataFrame, v4_meta: str, v5_meta: str, date: str) -> dict:
    total = len(merged)
    higher = int((merged["delta"] > 0.001).sum())
    lower = int((merged["delta"] < -0.001).sum())
    same = total - higher - lower

    # CVSS coverage disclosure
    cvss_with_data = int((merged["cvss_severity"] != "").sum())
    cvss_pct = round(cvss_with_data / total * 100, 1)

    # Threshold crossing analysis — include base rates for context
    crossings = {}
    for t in [0.05, 0.1, 0.2, 0.5]:
        v4_above = int((merged["epss_v4"] >= t).sum())
        v4_below = int((merged["epss_v4"] < t).sum())
        crossed_up = int(((merged["epss_v4"] < t) & (merged["epss_v5"] >= t)).sum())
        crossed_down = int(((merged["epss_v4"] >= t) & (merged["epss_v5"] < t)).sum())
        crossings[str(t)] = {
            "threshold": t,
            "v4_above": v4_above,
            "v4_below": v4_below,
            "crossed_up": crossed_up,
            "crossed_down": crossed_down,
            "net": crossed_up - crossed_down,
        }

    # No-CVSS CVE behavior: how does V5 treat CVEs with no vendor severity signal?
    no_cvss = merged[merged["cvss_severity"] == ""]
    no_cvss_count = len(no_cvss)
    no_cvss_median_v4 = r(no_cvss["epss_v4"].median()) if no_cvss_count > 0 else None
    no_cvss_median_v5 = r(no_cvss["epss_v5"].median()) if no_cvss_count > 0 else None
    no_cvss_pct_higher = round(
        float((no_cvss["delta"] > 0.001).sum()) / max(no_cvss_count, 1) * 100, 1
    ) if no_cvss_count > 0 else None

    return {
        "total_cves": total,
        "v4_model": v4_meta,
        "v5_model": v5_meta,
        "score_date": date,
        "pct_higher_in_v5": round(higher / total * 100, 2),
        "pct_lower_in_v5": round(lower / total * 100, 2),
        "pct_same": round(same / total * 100, 2),
        "count_higher": higher,
        "count_lower": lower,
        "count_same": same,
        "v4_mean": r(merged["epss_v4"].mean()),
        "v4_median": r(merged["epss_v4"].median()),
        "v5_mean": r(merged["epss_v5"].mean()),
        "v5_median": r(merged["epss_v5"].median()),
        "delta_mean": r(merged["delta"].mean()),
        "delta_median": r(merged["delta"].median()),
        "delta_max": r(merged["delta"].max()),
        "delta_min": r(merged["delta"].min()),
        "cvss_with_data": cvss_with_data,
        "cvss_pct": cvss_pct,
        "no_cvss_count": no_cvss_count,
        "no_cvss_median_v4": no_cvss_median_v4,
        "no_cvss_median_v5": no_cvss_median_v5,
        "no_cvss_pct_higher": no_cvss_pct_higher,
        "threshold_crossings": crossings,
    }


def build_scatter(merged: pd.DataFrame, n: int = 5000) -> list:
    """Stratified sample: proportional across score buckets."""
    df = merged[["cve", "epss_v4", "epss_v5", "delta", "cvss_severity"]].dropna(subset=["epss_v4", "epss_v5"])
    df = df.copy()
    df["bucket"] = pd.cut(df["epss_v5"], bins=10, labels=False)
    sampled = df.groupby("bucket", group_keys=False).apply(
        lambda g: g.sample(min(len(g), max(1, int(n * len(g) / len(df)))), random_state=42)
    )
    if len(sampled) > n:
        sampled = sampled.sample(n, random_state=42)
    return [
        {"cve": row.cve, "v4": r(row.epss_v4), "v5": r(row.epss_v5), "d": r(row.delta), "sev": row.cvss_severity or ""}
        for row in sampled.itertuples()
    ]



def build_by_cwe(merged: pd.DataFrame, top_n: int = 40) -> list:
    df = merged[merged["cwe"].notna() & (merged["cwe"] != "")]
    grp = df.groupby("cwe").agg(
        count=("cve", "count"),
        avg_v4=("epss_v4", "mean"),
        avg_v5=("epss_v5", "mean"),
        avg_delta=("delta", "mean"),
        median_v4=("epss_v4", "median"),
        median_v5=("epss_v5", "median"),
    ).reset_index()
    grp = grp.nlargest(top_n, "count")
    return [
        {
            "cwe": row.cwe,
            "name": CWE_NAMES.get(row.cwe, row.cwe),
            "count": int(row.count),
            "avg_v4": r(row.avg_v4),
            "avg_v5": r(row.avg_v5),
            "avg_delta": r(row.avg_delta),
            "median_v4": r(row.median_v4),
            "median_v5": r(row.median_v5),
        }
        for row in grp.itertuples()
    ]


VECTOR_LABELS = {
    "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    "AC": {"L": "Low", "H": "High"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "R": "Required"},
    "S": {"U": "Unchanged", "C": "Changed"},
    "C": {"H": "High", "L": "Low", "N": "None"},
    "I": {"H": "High", "L": "Low", "N": "None"},
    "A": {"H": "High", "L": "Low", "N": "None"},
}


def build_by_cvss_component(merged: pd.DataFrame) -> dict:
    df = merged[merged["cvss_vector"].notna() & (merged["cvss_vector"] != "")].copy()
    parsed = df["cvss_vector"].apply(parse_cvss_vector)
    result = {}
    for metric, labels in VECTOR_LABELS.items():
        col = f"m_{metric}"
        df[col] = parsed.apply(lambda p, m=metric: p.get(m, ""))
        grp = df[df[col] != ""].groupby(col).agg(
            count=("cve", "count"),
            avg_v4=("epss_v4", "mean"),
            avg_v5=("epss_v5", "mean"),
            avg_delta=("delta", "mean"),
        ).reset_index()
        result[metric] = [
            {
                "value": getattr(row, col),
                "label": labels.get(getattr(row, col), getattr(row, col)),
                "count": int(row.count),
                "avg_v4": r(row.avg_v4),
                "avg_v5": r(row.avg_v5),
                "avg_delta": r(row.avg_delta),
            }
            for row in grp.itertuples()
        ]
    return result


def build_by_severity(merged: pd.DataFrame) -> list:
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    df = merged.copy()
    df["cvss_severity"] = df["cvss_severity"].fillna("").str.upper()
    df = df[df["cvss_severity"].isin(order)]
    grp = df.groupby("cvss_severity").agg(
        count=("cve", "count"),
        avg_v4=("epss_v4", "mean"),
        avg_v5=("epss_v5", "mean"),
        avg_delta=("delta", "mean"),
        median_v4=("epss_v4", "median"),
        median_v5=("epss_v5", "median"),
    ).reset_index()
    grp["_ord"] = grp["cvss_severity"].apply(order.index)
    grp = grp.sort_values("_ord")
    return [
        {
            "severity": row.cvss_severity or "Unknown",
            "count": int(row.count),
            "avg_v4": r(row.avg_v4),
            "avg_v5": r(row.avg_v5),
            "avg_delta": r(row.avg_delta),
            "median_v4": r(row.median_v4),
            "median_v5": r(row.median_v5),
        }
        for row in grp.itertuples()
    ]


EXCLUDE_VALUES = {"n/a", "na", "none", "unknown", "not applicable", "-"}

def build_by_field(merged: pd.DataFrame, field: str, top_n: int) -> list:
    df = merged[
        merged[field].notna() &
        (merged[field] != "") &
        (merged[field].str.strip() != "") &
        (~merged[field].str.strip().str.lower().isin(EXCLUDE_VALUES))
    ].copy()
    grp = df.groupby(field).agg(
        count=("cve", "count"),
        avg_v4=("epss_v4", "mean"),
        avg_v5=("epss_v5", "mean"),
        avg_delta=("delta", "mean"),
        median_v4=("epss_v4", "median"),
        median_v5=("epss_v5", "median"),
    ).reset_index()
    grp = grp.nlargest(top_n, "count")
    return [
        {
            field: getattr(row, field),
            "count": int(row.count),
            "avg_v4": r(row.avg_v4),
            "avg_v5": r(row.avg_v5),
            "avg_delta": r(row.avg_delta),
            "median_v4": r(row.median_v4),
            "median_v5": r(row.median_v5),
        }
        for row in grp.itertuples()
    ]


def _mover_record(row) -> dict:
    # Parse CVE year from ID (e.g., CVE-2012-1446 -> "2012")
    cve_year = row.cve.split("-")[1] if row.cve.startswith("CVE-") and row.cve.count("-") >= 2 else ""
    # Suppress placeholder vendor/product values in display
    vendor = row.vendor if row.vendor.strip().lower() not in EXCLUDE_VALUES else ""
    product = row.product if row.product.strip().lower() not in EXCLUDE_VALUES else ""
    return {
        "cve": row.cve,
        "year": cve_year,
        "v4": r(row.epss_v4),
        "v5": r(row.epss_v5),
        "delta": r(row.delta),
        "percentile_v4": r(row.percentile_v4),
        "percentile_v5": r(row.percentile_v5),
        "severity": row.cvss_severity or "",
        "cvss_score": r(row.cvss_score),
        "vendor": vendor,
        "product": product,
        "cwe": row.cwe or "",
        "cwe_name": CWE_NAMES.get(row.cwe, "") if row.cwe else "",
        "cna": row.cna or "",
        "description": row.description or "",
    }


def build_movers(merged: pd.DataFrame, top_n: int = 50) -> dict:
    """Return top upgrades and top downgrades separately."""
    df = merged.copy()
    upgrades = df[df["delta"] > 0].nlargest(top_n, "delta")
    downgrades = df[df["delta"] < 0].nsmallest(top_n, "delta")
    return {
        "upgrades": [_mover_record(row) for row in upgrades.itertuples()],
        "downgrades": [_mover_record(row) for row in downgrades.itertuples()],
    }


def read_model_version(gz_bytes: bytes) -> str:
    with gzip.open(io.BytesIO(gz_bytes), "rt") as f:
        first = f.readline()
    m = re.search(r"model_version:([^,\s]+)", first)
    return m.group(1) if m else "unknown"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--date", default="2026-05-22")
    ap.add_argument("--cve-dir", default=os.path.expanduser("~/Data/cvelistV5"))
    ap.add_argument("--out-dir", default="docs/data")
    ap.add_argument("--cache-dir", default=".cache")
    ap.add_argument("--no-download", action="store_true")
    args = ap.parse_args()

    date = args.date
    year = date.split("-")[0]
    cve_dir = Path(args.cve_dir)
    out_dir = Path(args.out_dir)
    cache_dir = Path(args.cache_dir)

    v4_url = EPSS_V4_URL.format(year=year, date=date)
    v5_url = EPSS_V5_URL.format(date=date)

    v4_cache = cache_dir / f"epss_v4_{date}.csv.gz"
    v5_cache = cache_dir / f"epss_v5_{date}.csv.gz"

    print("=== EPSS V4 vs V5 Build Pipeline ===", flush=True)
    print(f"Date: {date}", flush=True)
    print(f"CVE dir: {cve_dir}", flush=True)

    print("\n[1/4] Loading EPSS scores...", flush=True)
    v4 = download_epss(v4_url, v4_cache, no_download=args.no_download)
    v4_meta = read_model_version(v4_cache.read_bytes())
    v5 = download_epss(v5_url, v5_cache, no_download=args.no_download)
    v5_meta = read_model_version(v5_cache.read_bytes())
    print(f"V4 model: {v4_meta}", flush=True)
    print(f"V5 model: {v5_meta}", flush=True)
    v4 = v4.rename(columns={"epss": "epss_v4", "percentile": "percentile_v4"})
    v5 = v5.rename(columns={"epss": "epss_v5", "percentile": "percentile_v5"})
    merged = pd.merge(v4, v5, on="cve", how="inner")
    merged["delta"] = merged["epss_v5"] - merged["epss_v4"]
    print(f"Merged: {len(merged):,} CVEs", flush=True)

    print("\n[2/4] Loading CVE enrichment data...", flush=True)
    cve_data = load_cve_data(cve_dir / "cves")
    merged = pd.merge(merged, cve_data, on="cve", how="left")
    # Clean string fields
    for col in ["vendor", "product", "cna", "cwe", "cvss_severity", "cvss_vector", "description"]:
        merged[col] = merged[col].fillna("").astype(str).str.strip()

    print("\n[3/4] Computing aggregations...", flush=True)

    # Score distribution
    v4_h, edges = np.histogram(merged["epss_v4"].dropna(), bins=100, range=(0, 1))
    v5_h, _ = np.histogram(merged["epss_v5"].dropna(), bins=100, range=(0, 1))
    score_dist = {
        "bins": [round(float(edges[i]), 2) for i in range(len(edges) - 1)],
        "v4": v4_h.tolist(),
        "v5": v5_h.tolist(),
    }

    # Delta distribution
    delta_h, delta_edges = np.histogram(merged["delta"].dropna(), bins=100, range=(-1, 1))
    delta_dist = {
        "bins": [round(float(delta_edges[i]), 3) for i in range(len(delta_edges) - 1)],
        "counts": delta_h.tolist(),
    }

    print("\n[4/4] Writing JSON files...", flush=True)
    write_json(out_dir / "summary.json", build_summary(merged, v4_meta, v5_meta, date))
    write_json(out_dir / "score_distribution.json", score_dist)
    write_json(out_dir / "delta_distribution.json", delta_dist)
    write_json(out_dir / "scatter.json", build_scatter(merged))
    write_json(out_dir / "by_cwe.json", build_by_cwe(merged))
    write_json(out_dir / "by_cvss_component.json", build_by_cvss_component(merged))
    write_json(out_dir / "by_severity.json", build_by_severity(merged))
    write_json(out_dir / "by_vendor.json", build_by_field(merged, "vendor", 30))
    write_json(out_dir / "by_product.json", build_by_field(merged, "product", 50))
    write_json(out_dir / "by_cna.json", build_by_field(merged, "cna", 30))
    write_json(out_dir / "movers.json", build_movers(merged))
    write_json(out_dir / "meta.json", {
        "built_at": datetime.now(timezone.utc).isoformat(),
        "score_date": date,
        "v4_model": v4_meta,
        "v5_model": v5_meta,
        "total_cves": len(merged),
        "cve_enriched": int(merged["cwe"].ne("").sum()),
    })
    print("\nDone!", flush=True)


if __name__ == "__main__":
    main()
