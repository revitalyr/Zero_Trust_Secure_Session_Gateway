// Explicitly disable module export in Boost.UT to prevent scanner confusion
#define BOOST_UT_DISABLE_MODULE
#include <chrono> // For std::chrono::system_clock operators
#include <boost/ut.hpp>

// C++23 module imports
import zerossg.session.session_manager;
import zerossg.types;
import zerossg.interfaces;
import zerossg.result;

// Корректные алиасы типов для тестов
using User = zerossg::User;
using Role = zerossg::Role;
using String = zerossg::String;
using SessionManager = zerossg::SessionManager;
using Session = zerossg::Session;

struct SessionManagerFixture {
    std::unique_ptr<SessionManager> session_manager;

    SessionManagerFixture() {
        session_manager = std::make_unique<SessionManager>();
    }
};

boost::ut::suite SessionManagerSuite = [] {
    using namespace boost::ut;

    "CreateSession"_test = [] {
        SessionManagerFixture fixture;
        // В Role используем прямой доступ к перечислению
        User test_user("testuser", "hash", Role::OPERATOR);
        String client_ip = "192.168.1.100";
        String target_service = "ssh";

        // Создание сессии. std::expected проверяется через .has_value()
        auto session_result = fixture.session_manager->create_session(test_user, client_ip, target_service);
        expect(session_result.has_value());
        expect(!session_result.value().empty());

        // Получение сессии
        auto get_result = fixture.session_manager->get_session(session_result.value());
        expect(get_result.has_value());

        // Проверка полей структуры Session из types.ixx
        expect(get_result->user_name() == "testuser"); // Corrected from user_id
        expect(get_result->client_ip() == client_ip);
        expect(get_result->target_service() == target_service);

        // Проверка активности через время истечения
        expect(get_result->expires_at() > std::chrono::system_clock::now());
    };

    "SessionValidation"_test = [] {
        SessionManagerFixture fixture;
        User test_user("testuser", "hash", Role::VIEWER);
        String client_ip = "192.168.1.101";
        String target_service = "web-admin";

        auto session_result = fixture.session_manager->create_session(test_user, client_ip, target_service);
        expect(session_result.has_value());
        String session_id = session_result.value();

        // Валидация сессии
        auto validate_result = fixture.session_manager->is_session_valid(session_id);
        expect(validate_result.has_value() && validate_result.value() == true);

        // Завершение сессии
        auto terminate_result = fixture.session_manager->terminate_session(session_id);
        expect(terminate_result.has_value());

        // После завершения валидация должна вернуть ошибку или false
        auto validate_after = fixture.session_manager->is_session_valid(session_id);
        expect(!(validate_after.has_value() && validate_after.value() == true));
    };

    "SessionUpdate"_test = [] {
        SessionManagerFixture fixture;
        User test_user("testuser", "hash", Role::ADMIN);
        String client_ip = "192.168.1.102";
        String target_service = "database";

        auto session_result = fixture.session_manager->create_session(test_user, client_ip, target_service);
        expect(session_result.has_value());
        String session_id = session_result.value();

        auto get_result = fixture.session_manager->get_session(session_id);
        expect(get_result.has_value());
        Session session = get_result.value();

        // Обновление: например, меняем время истечения
        session.set_expires_at(std::chrono::system_clock::now() - std::chrono::hours(1));
        auto update_result = fixture.session_manager->update_session(session_id, session);
        expect(update_result.has_value());

        // Проверка, что изменения применились
        auto final_get = fixture.session_manager->get_session(session_id);
        if (final_get.has_value()) {
            expect(final_get->expires_at() < std::chrono::system_clock::now());
        }
    };

    "ActiveSessionsList"_test = [] {
        SessionManagerFixture fixture;
        User user1("user1", "hash", Role::OPERATOR);
        User user2("user2", "hash", Role::VIEWER);

        fixture.session_manager->create_session(user1, "192.168.1.104", "ssh");
        fixture.session_manager->create_session(user2, "192.168.1.105", "web-admin");

        auto active_result = fixture.session_manager->get_active_sessions();
        expect(active_result.has_value());
        expect(active_result->size() == 2);
    };

    "CleanupExpiredSessions"_test = [] {
        SessionManagerFixture fixture;
        User test_user("testuser", "hash", Role::VIEWER);

        auto session_result = fixture.session_manager->create_session(test_user, "192.168.1.111", "web-admin");
        expect(session_result.has_value());
        String session_id = session_result.value();

        // Искусственно «протухаем» сессию
        auto get_result = fixture.session_manager->get_session(session_id);
        Session session = get_result.value();
        session.set_expires_at(std::chrono::system_clock::now() - std::chrono::seconds(10));
        fixture.session_manager->update_session(session_id, session);

        // Очистка
        auto cleanup_result = fixture.session_manager->cleanup_expired_sessions();
        expect(cleanup_result.has_value());

        // Теперь сессии не должно быть в списке активных
        auto active_result = fixture.session_manager->get_active_sessions();
        for (const auto& s : *active_result) {
            expect(s.user_name() != "testuser"); // Corrected from user_id
        }
    };
};