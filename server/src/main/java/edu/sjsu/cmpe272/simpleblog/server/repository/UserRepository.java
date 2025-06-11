package edu.sjsu.cmpe272.simpleblog.server.repository;

import edu.sjsu.cmpe272.simpleblog.server.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, String> {

}
