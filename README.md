# Extended Linux Rule Set for Sysmon

**Extended Linux Rule Set for Sysmon (ELRS-Sysmon)** is a project aimed at providing an actionable and up-to-date set of rules mapped to the **MITRE ATT&CK®** framework for Linux systems that use Sysmon as part of their monitoring stack.

The goal of the project is to monitor the most important areas of the operating system and map each technique to MITRE ATT&CK® where possible, while keeping the generated noise to a minimum. Rather than using a "include all" approach, the current design focuses on collecting the most important information—particularly information that is likely to be associated with threats and threat actors.

The ruleset is still under development and has not been thoroughly tested. Some rules may not work correctly, while others may generate a significant amount of noise depending on your system configuration.

The current ruleset has primarily been tested and optimized for **Debian-based systems**. Additional tuning may be required if you decide to use this ruleset on other distributions, such as **Red Hat-based distributions**.

> **Warning:** Please test this ruleset in a lab environment before deploying it to production.

## Design

**ELRS-Sysmon** is based on [MSTIC-Sysmon](https://github.com/microsoft/MSTIC-Sysmon/tree/main/linux/configs) and the rules presented in the [Hunting for Persistence in Linux](https://www.activecountermeasures.com/hunting-for-persistence-in-linux-part-1-auditd-sysmon-osquery-and-webshells/) blog series. However, this project includes additional rules and improvements intended to increase detection coverage while minimizing the generated noise.

One aspect of the ruleset that requires some explanation is the use of the **CurrentDirectory** field.

For example, suppose an attacker attempts to modify or remove logs from `/var/log/` using the following command:

```bash
nano /var/log/dpkg.log
```
Because the file is being edited rather than explicitly deleted, this activity can only be detected through EventCode 1, the ProcessCreate event. We can detect this activity using a rule such as:


```xml
		<Rule name="TechniqueID=T1685.006 ,TechniqueName=Disable or Modify Tools: Clear Linux or Mac System Logs" groupRelation="and">

		  <Image condition="contains any">/python;/perl;/unlink;/truncate;/rm;/shred;/nano;/vim;/vi;/mousepad;/sed</Image>
		  <CommandLine condition="contains">/var/log/</CommandLine>
        </Rule>
```

However, what happens if the attacker does not use the full path when attempting to edit or delete the file?

They could instead change their approach:

```bash
cd /var/log/
nano dpkg.log
```

In this case, the previous rule would not trigger because the command line does not contain `/var/log/`.

This is where rules using **CurrentDirectory** can help:

```xml
		<Rule name="TechniqueID=T1685.006 ,TechniqueName=Disable or Modify Tools: Clear Linux or Mac System Logs" groupRelation="and">

		 <Image condition="contains any">/python;/perl;/unlink;/truncate;/rm;/shred;/nano;/vim;/vi;/mousepad;/sed</Image>
		  <CurrentDirectory condition="is">/var/log</CurrentDirectory>
		  <CommandLine condition="contains any">*;log;gz;sysmon;btmp;wtmp;journal;messages;httpd;secure</CommandLine>
        </Rule>
```

With this approach, **CurrentDirectory** is checked alongside suspicious images and command-line arguments that may reference log files. As a result, the attacker's second method can also be detected.

That said, using **CurrentDirectory** in this way can also introduce false positives. Although the expected volume should remain relatively low, it can be further reduced by creating more precise conditions and triggers for individual rules.

# Roadmap and Contributions
Updates, improvements, and new rules will be added over time. However, there are limitations both within Sysmon itself and in the amount of testing and development that can currently be performed for ELRS-Sysmon.

Linux has a large number of distributions, versions, and configurations. Ensuring that the ruleset works correctly across all of them while keeping the generated noise to a minimum is extremely difficult without help from the community.

Although Sysmon cannot currently serve as a complete, standalone monitoring solution for Linux systems, it can still provide significant value when used correctly as part of a broader monitoring stack.

The goal of ELRS-Sysmon is therefore to develop a ruleset that addresses the practical needs of security defenders while continuously adapting to the evolving threat landscape.

Community contributions, testing, feedback, and suggestions are greatly appreciated. If you find an issue, encounter a false positive, or have an idea for a new detection, please consider opening an issue or contributing a rule.
