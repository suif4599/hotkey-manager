#ifndef DEAMON_CONDITION_H
#define DEAMON_CONDITION_H

#include <libevdev-1.0/libevdev/libevdev.h>
#include <vector>
#include <string>
#include <set>
#include <cstdint>

namespace hotkey_manager {

enum class Token {
    KEY,
    PLUS,
    MODIFIER,
    LEFT_PAREN,
    RIGHT_PAREN,
    COMMA,
    NUMBER
};

class Keyboard;

class Modifier {
protected:
    std::string name;
    explicit Modifier(const std::string& mod_name = "Base"): name(mod_name) {}
public:
    virtual ~Modifier() = default;
    static Modifier* from_string(
        const std::string& mod_str,
        int64_t durationMs = 500
    );
    static Modifier* from_modifier(const Modifier& modifier);
    const std::string to_string() const;
    virtual bool activate();
    virtual void deactivate();
    virtual int64_t getArgs() const;
};

class NoneModifier : public Modifier {
public:
    NoneModifier(): Modifier("None") {}
    bool activate() override { return true; }
    void deactivate() override {}
    int64_t getArgs() const override;
};

class DoubleModifier : public Modifier {
    bool enableDeactivate;
    bool enableReleaseTimer;
    int64_t releaseTimestampMs;
    int64_t durationMs;
public:
    explicit DoubleModifier(int64_t durationMs = 500);
    bool activate() override;
    void deactivate() override;
    int64_t getArgs() const override;
};

class HoldModifier : public Modifier {
    int64_t pressTimestampMs;
    int64_t durationMs;
public:
    explicit HoldModifier(int64_t durationMs = 500);
    bool activate() override;
    void deactivate() override;
    int64_t getArgs() const override;
};

class Condition {
    std::vector<Condition*> conds;
    Modifier* modifier;
    mutable std::string condition_str;
    Condition(
        std::vector<std::pair<Token, std::string>>::const_iterator begin,
        std::vector<std::pair<Token, std::string>>::const_iterator end,
        const Modifier& modifier = NoneModifier()
    );
protected:
    std::set<key_t> related_keys;
    bool hasActivated;
public:
    Condition();
    Condition(const Condition& other);
    virtual ~Condition();
    static Condition from_string(const std::string& condStr);
    virtual bool check(const Keyboard& keyboard);
    virtual const std::string& to_string() const;
    virtual size_t hash() const;
    virtual bool operator==(const Condition& other) const;
};

class SingleKeyCondition : public Condition {
    key_t key;
public:
    explicit SingleKeyCondition(key_t key_);
    ~SingleKeyCondition() override = default;
    bool check(const Keyboard& keyboard) override;
    const std::string& to_string() const override;
    size_t hash() const override;
    bool operator==(const Condition& other) const override;
};

} // namespace hotkey_manager

namespace std {
    template <>
    struct hash<hotkey_manager::Condition> {
        size_t operator()(const hotkey_manager::Condition& cond) const {
            return cond.hash();
        }
    };
}

#endif // DEAMON_CONDITION_H