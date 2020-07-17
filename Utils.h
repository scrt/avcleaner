//
// Created by Vladimir on 20.06.20.
//

#ifndef AVCLEANER_UTILS_H
#define AVCLEANER_UTILS_H

#include <iostream>

namespace Utils {


    /**
     * @brief generates a random string of size Length.
     * @param Length desired length of the generated string.
     * @return a random string of size Length.
     */
    extern std::string randomString(unsigned long Length);

    /**
     * used to replace a string literal by a variable's identifier
     * must not collide with existing identifiers.
     * Format: 12-first characters, letters only + random part
     * TODO: remember allocated identifiers for collision prevention
     * TODO: extract constants into readable identifiers.
     * @param StrLiteral the string literal
     */
    extern std::string translateStringToIdentifier(const std::string &StrLiteral);


    /**
     * strip metacharacters decorating a string.
     * For instance, L"ntdll" -> ntdll
     * @param Argument the string to be cleaned.
     */
    extern void cleanParameter(std::string &Argument);


    /**
     * @brief declares and instantiate a variable holding a string that was moved out from a function's arguments.
     * @param StringIdentifier the new variable identifier.
     * @param StringValue the actual value of the string literal.
     * @return the generated code snippet.
     */
    extern std::string generateVariableDeclaration(const std::string &StringIdentifier, const std::string &StringValue, std::string StringType="");
};

#endif //AVCLEANER_UTILS_H
