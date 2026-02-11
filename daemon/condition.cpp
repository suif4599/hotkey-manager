#include "daemon/condition.h"
#include "daemon/keyboard.h"
#include "ipc/uds.h"
#include <regex>
#include <stdexcept>
#include <unordered_map>
#include <algorithm>

using namespace hotkey_manager;

namespace hotkey_manager {


Modifier* Modifier::from_string(
    const std::string& mod_str,
    int64_t durationMs
) {
    if (mod_str.empty() || mod_str == "None")
        return new NoneModifier();
    if (mod_str == "Double")
        return new DoubleModifier(durationMs);
    if (mod_str == "Hold")
        return new HoldModifier(durationMs);
    throw std::invalid_argument("Unknown modifier: " + mod_str);
}

Modifier* Modifier::from_modifier(const Modifier& modifier) {
    int64_t args = modifier.getArgs();
    if (args == -1)
        return from_string(modifier.to_string());
    return from_string(modifier.to_string(), args);
}

const std::string Modifier::to_string() const {
    return name;
}

bool Modifier::activate() {
    throw std::logic_error("Modifier::activate shouldn't be called in the program");
}

void Modifier::deactivate() {
    throw std::logic_error("Modifier::deactivate shouldn't be called in the program");
}

int64_t Modifier::getArgs() const {
    throw std::logic_error("Modifier::getArgs shouldn't be called in the program");
}

int64_t NoneModifier::getArgs() const {
    return -1;
}

DoubleModifier::DoubleModifier(int64_t durationMs)
: Modifier("Double")
, enableDeactivate(false)
, enableReleaseTimer(false)
, releaseTimestampMs(0)
, durationMs(durationMs) {};

bool DoubleModifier::activate() {
    if (enableReleaseTimer) {
        int64_t currentTimestampMs = getTimestampMs();
        enableReleaseTimer = false; // Reset the timer
        if (currentTimestampMs - releaseTimestampMs <= durationMs) {
            enableDeactivate = false;
            return true;
        }
        // Timeout is equivalent to a new press
    }
    enableDeactivate = true;
    return false;
}

void DoubleModifier::deactivate() {
    if (enableDeactivate) {
        enableReleaseTimer = true;
        enableDeactivate = false;
        releaseTimestampMs = getTimestampMs();
    }
}

int64_t DoubleModifier::getArgs() const {
    return durationMs;
}

HoldModifier::HoldModifier(int64_t durationMs)
: Modifier("Hold")
, pressTimestampMs(0)
, durationMs(durationMs) {};

bool HoldModifier::activate() {
    int64_t currentTimestampMs = getTimestampMs();
    if (currentTimestampMs - pressTimestampMs >= durationMs) {
        return true;
    }
    pressTimestampMs = currentTimestampMs;
    return false;
}

void HoldModifier::deactivate() {
    pressTimestampMs = 0;
}

int64_t HoldModifier::getArgs() const {
    return durationMs;
}

static std::vector<std::pair<Token, std::string>> tokenize(const std::string& cond_str) {
    static const std::regex modifierRe {"^(None|Double|Hold)"};
    static const std::regex keyRe {"^\\w+"};
    static const std::regex spaceRe {"^\\s+"};
    static const std::regex numberRe {"^\\d+"};
    std::vector<std::pair<Token, std::string>> tokens;
    std::string s = cond_str;
    while (!s.empty()) {
        std::smatch match;
        if (std::regex_search(s, match, numberRe)) {
            tokens.push_back({Token::NUMBER, match.str(0)});
            s = s.substr(match.length(0));
        } else if (std::regex_search(s, match, modifierRe)) {
            tokens.push_back({Token::MODIFIER, match.str(0)});
            s = s.substr(match.length(0));
        } else if (std::regex_search(s, match, keyRe)) {
            tokens.push_back({Token::KEY, match.str(0)});
            s = s.substr(match.length(0));
        } else if (std::regex_search(s, match, spaceRe)) {
            s = s.substr(match.length(0));
            continue;
        }  else if (s[0] == '+') {
            tokens.push_back({Token::PLUS, "+"});
            s = s.substr(1);
        } else if (s[0] == '(') {
            tokens.push_back({Token::LEFT_PAREN, "("});
            s = s.substr(1);
        } else if (s[0] == ')') {
            tokens.push_back({Token::RIGHT_PAREN, ")"});
            s = s.substr(1);
        } else if (s[0] == ',') {
            tokens.push_back({Token::COMMA, ","});
            s = s.substr(1);
        } else {
            throw std::invalid_argument("Invalid token at the beginning of \"" + s + "\"");
        }
    }
    return tokens;
}

Condition::Condition()
: conds()
, modifier(new NoneModifier())
, condition_str("NULL")
, related_keys()
, hasActivated(false) {}

Condition::Condition(const Condition& other)
: conds(other.conds)
, modifier(Modifier::from_modifier(*other.modifier))
, condition_str("NULL")
, related_keys(other.related_keys)
, hasActivated(false) {}

Condition::Condition(
    std::vector<std::pair<Token, std::string>>::const_iterator begin,
    std::vector<std::pair<Token, std::string>>::const_iterator end,
    const Modifier& modifier
)
: conds()
, modifier(Modifier::from_modifier(modifier))
, condition_str("NULL")
, related_keys() {
    auto it = begin;
    while (it != end) {
        switch (it->first) {
            case Token::KEY: {
                key_t keycode;
                try {
                    keycode = KeyMapper::getInstance()[it->second];
                } catch (const std::out_of_range&) {
                    throw std::invalid_argument("Unknown key: " + it->second);
                }
                conds.push_back(
                    new SingleKeyCondition(keycode)
                );
                ++it;
                break;
            }
            case Token::PLUS: {
                ++it;
                break;
            }
            case Token::MODIFIER: {
                auto next = it + 1;
                if (next == end || next->first != Token::LEFT_PAREN) {
                    throw std::invalid_argument("Expected '(' after modifier");
                }
                int paren_count = 1;
                auto sub_begin = next + 1;
                auto sub_it = sub_begin;
                while (sub_it != end && paren_count > 0) {
                    if (sub_it->first == Token::LEFT_PAREN)
                        ++paren_count;
                    else if (sub_it->first == Token::RIGHT_PAREN)
                        --paren_count;
                    if (paren_count == 0)
                        break;
                    ++sub_it;
                }
                if (paren_count != 0) {
                    throw std::invalid_argument("Unmatched '(' in modifier");
                }
                bool flattenNone = false;
                if (
                    sub_it - 1 != sub_begin && (sub_it - 1) -> first == Token::NUMBER
                    && sub_it - 2 != sub_begin && (sub_it - 2) -> first == Token::COMMA
                ) {
                    // Duration is specified
                    int64_t durationMs = std::stoll((sub_it - 1)->second);
                    Modifier* sub_modifier = Modifier::from_string(it->second, durationMs);
                    conds.push_back(new Condition(sub_begin, sub_it - 2, *sub_modifier));
                    flattenNone = sub_modifier->to_string() == "None";
                    delete sub_modifier;
                } else {
                    Modifier* sub_modifier = Modifier::from_string(it->second);
                    conds.push_back(new Condition(sub_begin, sub_it, *sub_modifier));
                    flattenNone = sub_modifier->to_string() == "None";
                    delete sub_modifier;
                }
                it = sub_it + 1;

                // Flatten NoneModifier
                if (flattenNone) {
                    Condition* lastCond = conds.back();
                    conds.pop_back();
                    for (const auto& subCond : lastCond->conds) {
                        conds.push_back(subCond);
                    }
                    lastCond->conds.clear();
                    delete lastCond;
                }
                break;
            }
            case Token::LEFT_PAREN: {
                throw std::invalid_argument("Unexpected '(', it should follow a modifier");
            }
            case Token::RIGHT_PAREN: {
                throw std::invalid_argument("Unexpected ')'");
            }
            case Token::COMMA: {
                throw std::invalid_argument("Unexpected ','");
            }
            case Token::NUMBER: {
                throw std::invalid_argument("Unexpected number '" + it->second + "'");
            }
        }
    }
    
    for (const auto& cond : conds) {
        for (const auto& key : cond->related_keys) {
            related_keys.insert(key);
        }
    }
}

Condition::~Condition() {
    delete modifier;
    for (auto cond : conds) {
        delete cond;
    }
}

Condition Condition::from_string(const std::string& cond_str) {
    auto tokens = tokenize(cond_str);
    return Condition(tokens.cbegin(), tokens.cend());
}

bool Condition::isRelatedKey(key_t key) const {
    return related_keys.find(key) != related_keys.end();
}

bool Condition::check(const Keyboard& keyboard) {
    if (conds.empty())
        return false;
    auto it = std::find(related_keys.begin(), related_keys.end(), keyboard.lastUpdatedKey);
    // No related key is pressed or released, keep the previous state
    if (it == related_keys.end())
        return hasActivated;
    // All sub-conditions must be satisfied
    bool allReleased = true;
    bool anyReleased = false;
    for (const auto& cond : conds) {
        if (!cond->check(keyboard)) {
            hasActivated = false;
            anyReleased = true;
        } else {
            allReleased = false;
        }
    }
    if (allReleased)
        modifier->deactivate();
    if (anyReleased)
        return false;
    // Activate the modifier which adds extra conditions
    hasActivated = modifier->activate();
    return hasActivated;
}

const std::string& Condition::to_string() const {
    if (condition_str != "NULL") {
        return condition_str;
    }
    if (conds.empty()) {
        condition_str = modifier->to_string();
        return condition_str;
    }

    condition_str = modifier->to_string() + "(";
    for (size_t i = 0; i < conds.size(); ++i) {
        condition_str += conds[i]->to_string();
        if (i != conds.size() - 1)
            condition_str += " + ";
    }
    int64_t args = modifier->getArgs();
    if (args != -1) {
        condition_str += ", " + std::to_string(args);;
    }
    condition_str += ")";
    return condition_str;
}

size_t Condition::hash() const {
    return std::hash<std::string>()(to_string());
}

bool Condition::operator==(const Condition& other) const {
    return to_string() == other.to_string();
}

SingleKeyCondition::SingleKeyCondition(key_t key_): Condition(), key(key_) {
    related_keys.insert(key_);
}

bool SingleKeyCondition::check(const Keyboard& keyboard) {
    // SingleKeyCondition will never be a standalone condition and has always NoneModifier
    // It has at least a wrapper condition, so no need for more checks
    return keyboard.key_states[key];
}

const std::string& SingleKeyCondition::to_string() const {
    return KeyMapper::getInstance()[key];
}

size_t SingleKeyCondition::hash() const {
    return std::hash<std::string>()(to_string());
}

bool SingleKeyCondition::operator==(const Condition& other) const {
    return to_string() == other.to_string();
}

} // namespace hotkey_manager
