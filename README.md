# Web eID ASP.NET example

![European Regional Development Fund](https://github.com/open-eid/DigiDoc4-Client/blob/master/client/images/EL_Regionaalarengu_Fond.png)

This project is an example ASP.NET web application that shows how to implement strong authentication and digital signing with electronic ID smart cards using Web eID.

More information about the Web eID project is available on the project [website](https://web-eid.eu/).

The ASP.NET web application makes use of the following technologies:

-   ASP.NET MVC,
-   the Web eID authentication token validation library [_web-eid-authtoken-validation-dotnet_](https://github.com/web-eid/web-eid-authtoken-validation-dotnet),
-   the Web eID JavaScript library [_web-eid.js_](https://github.com/web-eid/web-eid.js),
-   the digital signing library [_libdigidocpp_](https://github.com/open-eid/libdigidocpp/tree/master/examples/DigiDocCSharp).

## Quickstart

Complete the steps below to run the example application in order to test authentication and digital signing with Web eID.

### 1. Configure the origin URL

One crucial step of the Web eID authentication token validation algorithm is verifying the token signature. The value that is signed contains the site origin URL (the URL serving the web application) to protect against man-in-the-middle attacks. Hence the site origin URL must be configured in application settings.

To configure the origin URL, add `OriginUrl` field in the application settings file  `appsettings.json`  as follows:
```json
{
  "OriginUrl": "https://example.org"
}
```
Note that the URL **must not end with a slash** `/`.

### 2. Configure the trusted certificate authority certificates

The algorithm, which performs the validation of the Web eID authentication token, needs to know which intermediate certificate authorities (CA) are trusted to issue the eID authentication certificates. CA certificates are loaded from `.cer` files in the profile-specific subdirectory of the  [`Certificates` resource directory](https://github.com/web-eid/web-eid-asp-dotnet-example/src/WebEid.AspNetCore.Example/Certificates). By default, Estonian eID test CA certificates are included in the `Development` profile and production CA certificates in the `Production` profile.

In case you need to provide your own CA certificates, add the `.cer` files to the  `src/WebEid.AspNetCore.Example/Certificates/{Dev,Prod}` profile-specific directory.

### 3. Setup the `libdigidocpp` library for signing
`libdigidocpp` is a library for creating, signing and verifying digitally signed documents according to XAdES and XML-DSIG standards. It is a C++ library that has [SWIG](http://swig.org/) bindings for C#.

Set up the `libdigidocpp` library as follows:

1.  Install the _libdigidocpp-3.14.4.msi_ package or higher. The installation packages are available from  [https://github.com/open-eid/libdigidocpp/releases](https://github.com/open-eid/libdigidocpp/releases).
2.  Copy the C# source files from the `libdigidocpp` installation folder `include\digidocpp_csharp` to the `src\WebEid.AspNetCore.Example\DigiDoc` folder.
3.  Copy all files from either the `x64` subfolder of the `libdigidocpp` installation folder to the example application build output folder `bin\...\net60` (after building, see next step). When building custom applications, choose `x64` if your application is 64-bit and `x86` if it is 32-bit.
4.  When running in the `Development` profile, create an empty file named `EE_T.xml` for TSL cache as described in the [_Using test TSL lists_](https://github.com/open-eid/libdigidocpp/wiki/Using-test-TSL-lists#preconditions) section of the `libdigidocpp` wiki.

Further information is available in the [libdigidocpp example C# application](https://github.com/open-eid/libdigidocpp/tree/master/examples/DigiDocCSharp) and in the [`libdigidocpp` wiki](https://github.com/open-eid/libdigidocpp/wiki).

### 4. Build the application

You need to have the [.NET 6.0 SDK](https://dotnet.microsoft.com/en-us/download/dotnet/6.0) installed for building the application package.
Build the application by running the following command in a terminal window under the `src` directory:

```cmd
dotnet build
```

### 5. Choose either the  `Development`  or  `Production`  profile

If you have a test eID card, use the  `Development`  profile. In this case access to paid services is not required, but you need to upload the authentication and signing certificates of the test card to the test OCSP responder database as described in section _[Using DigiDoc4j in test mode with the  `dev`  profile](https://github.com/web-eid/web-eid-spring-boot-example#using-digidoc4j-in-test-mode-with-the-dev-profile)_ of the Web eID Java example application documentation. The`Development` profile is activated by default.

If you only have a production eID card, use the  `Production`  profile. You can still test authentication without further configuration; however, for digital signing to work, you need access to a paid timestamping service as described in section [_Using DigiDoc4j in production mode with the  `prod`  profile_](https://github.com/web-eid/web-eid-spring-boot-example#using-digidoc4j-in-production-mode-with-the-prod-profile) of the Web eID Java example documentation.

You can specify the profile as an environment variable `ASPNETCORE_ENVIRONMENT` when running the application. To set the profile for the current session before starting the app using [`dotnet run`](https://docs.microsoft.com/en-us/dotnet/core/tools/dotnet-run), use the following command:
```cmd
set ASPNETCORE_ENVIRONMENT=Production
```

### 6. Run the application

Run the application with the following command in a terminal window under the `src` directory:

```cmd
dotnet run --project WebEid.AspNetCore.Example
```

This will activate the default `Development` profile and launch the built-in `kestrel` web server on HTTPS port 5001.

When the application has started, open https://localhost:5001 in your preferred web browser and follow instructions on the front page.

## Overview of the source code

The `src\WebEid.AspNetCore.Example` directory contains the ASP.NET application source code and resources. The subdirectories therein have the following purpose:
-   `wwwroot`: web server static content, including CSS and JavaScript files,
-   `Certificates`: CA certificates in profile-specific subdirectories,
-   `Controllers`: ASP.NET MVC controller for the welcome page and Web API controllers that provide endpoints for
    -   getting the challenge nonce used by the authentication token validation library,
    -   logging in,
    -   digital signing,
-   `DigiDoc`: contains the C# binding files of the `libdigidocpp` library; these files must be copied from the `libdigidocpp` installation directory `\include\digidocpp_csharp`,
-   `Pages`: Razor pages,
-   `Services`: Web eID signing service implementation that uses `libdigidocpp`.

## More information

See the [Web eID Java example application documentation](https://github.com/web-eid/web-eid-spring-boot-example) for more information, including answers to questions not answered below.

### Frequently asked questions

#### Why do I get the `System.ApplicationException: Failed to verify OCSP Responder certificate` error during signing?

You are running in the `Development` profile, but you have not created an empty file named `EE_T.xml` for TSL cache. Creating the file is mandatory and is described in more detail in the [_Using test TSL lists_](https://github.com/open-eid/libdigidocpp/wiki/Using-test-TSL-lists#preconditions) section of the `libdigidocpp` wiki.

#### Why do I get the `System.BadImageFormatException: An attempt was made to load a program with an incorrect format` error during signing?

You are using `libdigidocpp` DLLs for the wrong architecture. Copy files from the `x64` subfolder of the  `libdigidocpp` installation folder to right place as described in the section _3. Setup the `libdigidocpp` library for signing_ above. In case you get this error while developing a custom 32-bit application, copy files from the `x86` subfolder instead.
