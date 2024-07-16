# Cybersecurity ITS App

The Field Device Security Configuration Tool prototype will provide the ITS Vendor community with a reference design and example implementation of a mobile application and backend cloud service that can be used to guide ITS vendor customers in the secure configuration of ITS equipment. ITS vendors will be able to use the prototype to design their own custom versions of the mobile application and offer the application to their customer base.

Vendor-specific Field Device Security Configuration Tools will be used by ITS Technicians as an aid, providing them with the equipment vendor’s recommended security configuration details for the specific equipment type, connection type and intended use. The Field Device Security Configuration Tool is a mobile application that an ITS Technician can install on either an Android or iPhone device.

## Contents
This repository contains the server-side Amazon Web Services lambda functions for the Cybersecurity ITS application. These lambda functions implement the backend API functionality that connects the mobile application users with the vendor users of the backend application. These functions handle:
- User account administration: `adminDataFunction/`
- AWS resource management: `poolFunctions/`
- Data access management: `dataFunctions/` 
- API request handling: `requestConf_ocs/`
- User Authentication: `userFunctions_ocs/`

## Related Repositories:
 - [Cybersecurity-ITS-Frontend](https://github.com/usdot-fhwa-OPS/Cybersecurity-ITS-Frontend): The cloud-hosted user interface for Vendor users to upload and manage device configuration recommendations.
 - [ITS-Cybersecurity-ITS-Backend](https://github.com/usdot-fhwa-OPS/Cybersecurity-ITS-Backend): The backend cloud services to connect technician and vendor users.
