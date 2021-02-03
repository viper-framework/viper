![Viper](https://viper-framework.readthedocs.io/en/latest/_images/viper.png)

This is a fork of the Viper-Framework repository. It has been designed to address a number of design changes which may not be accepted by the original developers. The key focus of these changes is to increase the robustness and automation of the framework so that it may be used on a larger scale more reliably.  Specifically:

**v2.0-rc11**
* Binary storage indexing removed (all Malware is now stored in the root 'binaries' directory for each Project)
* The 'parent' field in the Malware table has been replaced with a Child Relation bridge table.
* Checks have been implemented to prevent cyclical hierarchy when adding a parent or child.
* Database().delete_analysis() has been implemented
* The 'report' command has been implemented - to show all notes and analysis for a sample.
* Modules will now run automatically when Malware is stored, depending on the mimetype. This is controlled by data/mime.conf
* A 'Project' table was added, allowing logical segmentation of Malware in Projects when using a singular database.
