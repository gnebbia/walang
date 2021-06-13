# walang

walang is a draft for a MAL language intended to be used for web applications
threat modeling.

This project has the following structure:

* The file `pom.xml` is the Maven configuration file of the project.
* The directory `src/main/mal` contains the MAL specification
  `walang.mal`, which is the MAL specification of **walang**.
* The directory `src/test/java/ml/gnebbia/walang/test`
  contains the unit tests of **walang**.


## Testing walang with example test cases

To test walang clone this repository by doing:

```sh
git clone https://github.com/gnebbia/walang
```

Then cd into the walang directory and execute the
test cases, maven will download all the required dependencies.

```
cd walang
mvn test
```

To only compile exampleLang into `.java` files, execute the following
command:

```
mvn generate-test-sources
```

To compile exampleLang into `.java` files and then compile these
`.java` files and the unit tests in `src/test/java` into `.class`
files, execute the following command:

```
mvn test-compile
```


To run a specific test class, execute the following command:

```
mvn test -Dtest=TestExampleLang
```

Where `TestExampleLang` is the test class.

## License

Copyright © 2021 [Giuseppe Nebbione](https://gnebbia.ml/)

All files distributed in the exampleLang project are licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).

See [`LICENSE`](LICENSE) for details.
